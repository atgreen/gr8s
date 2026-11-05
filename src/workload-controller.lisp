;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Reconcile real ReplicaSet and ReplicationController Pods and Deployment rollouts using durable owner
;;;; UIDs, optimistic mutations, observed Pod readiness and shared background
;;;; garbage collection. Repeated passes and process restarts are idempotent.

(in-package #:gr8s)

(defparameter *workload-clock* #'get-universal-time
  "Clock for observed readiness age and deployment progress deadlines.")

(defun workload-metadata (object)
  "Read an API object's metadata."
  (gethash "metadata" object))

(defun workload-owner-reference (owner)
  "Build the controller reference used for an actual dependent object."
  (core-object "apiVersion" (gethash "apiVersion" owner) "kind" (gethash "kind" owner)
               "name" (gethash "name" (workload-metadata owner)) "uid" (gethash "uid" (workload-metadata owner))
               "controller" t "blockOwnerDeletion" t))

(defun workload-controller-reference (object)
  "Find the unique controller owner without treating unrelated owners as controllers."
  (find-if (lambda (ref) (eq t (gethash "controller" ref)))
           (gethash "ownerReferences" (workload-metadata object) #())))

(defun workload-owned-p (object owner)
  "Require the exact current controller UID and API identity."
  (let ((ref (workload-controller-reference object)))
    (and ref (equal (gethash "uid" ref) (gethash "uid" (workload-metadata owner)))
         (equal (gethash "kind" ref) (gethash "kind" owner))
         (equal (gethash "apiVersion" ref) (gethash "apiVersion" owner)))))

(defun workload-current-unlocked (store resource object &key generation allow-deleting)
  "Check an owner against the store while its transaction lock is held."
  (let* ((metadata (workload-metadata object))
         (current (gethash (core-resource-key resource (gethash "namespace" metadata) (gethash "name" metadata))
                           (pod-store-resources store))))
    (when (and current (equal (gethash "uid" (workload-metadata current)) (gethash "uid" metadata))
               (or allow-deleting (not (gethash "deletionTimestamp" (workload-metadata current))))
               (or (not generation) (eql (gethash "generation" (workload-metadata current))
                                          (gethash "generation" metadata))))
      current)))

(defun update-workload-controller-status (store resource owner status)
  "Publish actual observations only for the same UID and desired generation."
  (with-store-lock (store)
    (let ((current (workload-current-unlocked store resource owner :generation t)))
      (when (and current (not (workload-equal-p status (gethash "status" current))))
        (let* ((copy (copy-core-object current)) (resources (copy-core-resource-index store))
               (revision (1+ (pod-store-resource-revision store))))
          (setf (gethash "status" copy) (copy-core-object status))
          (prepare-core-resource-metadata copy current revision)
          (setf (gethash (core-resource-key resource (gethash "namespace" (workload-metadata copy))
                                          (gethash "name" (workload-metadata copy))) resources) copy)
          (commit-core-resources store resources revision)
          copy)))))

(defun update-owned-workload (store resource owner transform)
  "Apply a controller write while rejecting name reuse by a replacement UID."
  (let ((metadata (workload-metadata owner)))
    (update-core-resource store resource (gethash "namespace" metadata) (gethash "name" metadata)
      (lambda (current)
        (unless (equal (gethash "uid" metadata) (gethash "uid" (workload-metadata current)))
          (core-resource-error 409 "Conflict" "Controller identity has changed"))
        (funcall transform current)))))

(defun workload-condition (previous type value reason message &key progress)
  "Keep transition history stable unless a real condition or progress change occurs."
  (let* ((old (find type previous :test #'equal :key (lambda (condition) (gethash "type" condition))))
         (now (current-timestamp (funcall *workload-clock*)))
         (same (and old (equal value (gethash "status" old))))
         (condition (core-object "type" type "status" value "reason" reason "message" message
                                 "lastTransitionTime" (if same (gethash "lastTransitionTime" old now) now))))
    (setf (gethash "lastUpdateTime" condition)
          (if (and same (not progress) (equal reason (gethash "reason" old))
                   (equal message (gethash "message" old))) (gethash "lastUpdateTime" old now) now))
    condition))

(defun workload-pod-status (reconciler pod)
  "Read truthful runtime status, tolerating a concurrent Pod deletion."
  (handler-case (reconcile-pod reconciler (pod-namespace pod) (pod-name pod))
    (kubernetes-error (condition)
      (if (= 404 (kubernetes-error-status-code condition)) (core-object "phase" "Unknown") (error condition)))))

(defun workload-active-pod-p (pod status)
  "Exclude terminating and terminal Pods from the ReplicaSet's active count."
  (and (not (deletion-requested-p pod))
       (not (member (gethash "phase" status) '("Succeeded" "Failed") :test #'equal))))

(defun workload-pod-available-p (status minimum)
  "Require Ready=True for the entire minimum ready duration."
  (let* ((ready (find-pod-condition (gethash "conditions" status) "Ready"))
         (time (and ready (ignore-errors (pod-deletion-time (gethash "lastTransitionTime" ready))))))
    (and (pod-status-ready-p status) (or (zerop minimum) (and time (>= (funcall *workload-clock*) (+ time minimum)))))))

(defun change-controller-pod-owner (store owner pod adopt
                                    &key (resource (workload-owner-resource owner)) tracking-finalizer
                                      (reference (workload-owner-reference owner)))
  "Adopt or release a Pod atomically with exact owner and dependent UID checks."
  (with-store-lock (store)
    (when (workload-current-unlocked store resource owner :generation t :allow-deleting (not adopt))
      (let ((current (gethash (pod-key (pod-namespace pod) (pod-name pod)) (pod-store-pods store))))
        (when (and current (equal (pod-uid current) (pod-uid pod))
                   (if adopt (and (not (deletion-requested-p current))
                                  (null (workload-controller-reference (pod-to-object current))))
                       (workload-owned-p (pod-to-object current) owner)))
          (let* ((object (copy-core-object (pod-to-object current))) (metadata (workload-metadata object))
                 (owners (remove-if (lambda (ref) (eq t (gethash "controller" ref))) (gethash "ownerReferences" metadata #()))))
            (setf (gethash "ownerReferences" metadata)
                  (if adopt (concatenate 'vector owners (vector reference)) owners))
            (when tracking-finalizer
              (let ((finalizers (gethash "finalizers" metadata #())))
                (setf (gethash "finalizers" metadata)
                      (if adopt
                          (if (find tracking-finalizer finalizers :test #'equal) finalizers
                              (concatenate 'vector finalizers (vector tracking-finalizer)))
                          (remove tracking-finalizer finalizers :test #'equal)))))
            (update-pod-unlocked store (parse-pod object) (pod-resource-version current))))))))

(defun replica-set-pods (reconciler owner &key claim)
  "Find exact-UID children, adopting matching orphans and releasing selector mismatches."
  (let* ((store (reconciler-store reconciler)) (metadata (workload-metadata owner))
         (selector (workload-spec-selector owner)) (result nil))
    (dolist (pod (list-pods store (gethash "namespace" metadata)))
      (let* ((object (pod-to-object pod)) (owned (workload-owned-p object owner))
             (matches (workload-selector-matches-p selector (gethash "labels" (workload-metadata object)))))
        (cond
          ((and claim owned (not matches)) (change-controller-pod-owner store owner pod nil))
          ((and owned matches) (push pod result))
          ((and claim matches (not (deletion-requested-p pod)) (null (workload-controller-reference object)))
           (let ((adopted (change-controller-pod-owner store owner pod t))) (when adopted (push adopted result)))))))
    (nreverse result)))

(defun workload-template-pod-object (owner)
  "Build the Pod a controller OWNER's template describes, with a generated name and owner reference."
  (let* ((template (gethash "template" (gethash "spec" owner)))
         (source-meta (gethash "metadata" template (core-object))) (metadata (core-object))
         (namespace (gethash "namespace" (workload-metadata owner)))
         (prefix (concatenate 'string (or (gethash "name" (workload-metadata owner)) "pod") "-")))
    (dolist (key '("labels" "annotations" "finalizers"))
      (when (gethash key source-meta) (setf (gethash key metadata) (copy-core-object (gethash key source-meta)))))
    (setf (gethash "generateName" metadata) (subseq prefix 0 (min 58 (length prefix)))
          (gethash "namespace" metadata) namespace
          (gethash "ownerReferences" metadata) (vector (workload-owner-reference owner)))
    (core-object "apiVersion" "v1" "kind" "Pod" "metadata" metadata
                 "spec" (copy-core-object (gethash "spec" template)))))

(defun create-replica-set-pod (store owner &key node-name labels)
  "Admit a real Pod and commit it only if its owner's UID and generation remain current.
NODE-NAME pins a daemon Pod to its node; LABELS is an alist added to the template's labels."
  (let ((object (workload-template-pod-object owner)))
    (when node-name (setf (gethash "nodeName" (gethash "spec" object)) node-name))
    (when labels
      (let ((metadata (workload-metadata object)))
        (unless (gethash "labels" metadata) (setf (gethash "labels" metadata) (core-object)))
        (loop for (key . value) in labels do (setf (gethash key (gethash "labels" metadata)) value))))
    (let ((pod (admit-in-cluster-pod store (parse-pod object :allow-generate-name t))))
      (with-store-lock (store)
        (when (workload-current-unlocked store (workload-owner-resource owner) owner :generation t)
          (create-pod-unlocked store pod))))))

(defun replica-set-observations (reconciler owner)
  "Return active child Pods paired with their actual statuses."
  (loop for pod in (replica-set-pods reconciler owner)
        for status = (workload-pod-status reconciler pod)
        when (workload-active-pod-p pod status) collect (cons pod status)))

(defun reconcile-replica-set (reconciler owner)
  "Scale actual children, preserving healthy siblings and reporting observed counts."
  (let* ((store (reconciler-store reconciler)) (spec (gethash "spec" owner))
         (desired (gethash "replicas" spec)) (failure nil) (failure-reason "FailedCreate"))
    (replica-set-pods reconciler owner :claim t)
    (let* ((active (replica-set-observations reconciler owner)) (delta (- desired (length active))))
      (handler-case
          (cond ((plusp delta) (loop repeat delta do (unless (create-replica-set-pod store owner) (return))))
                ((minusp delta)
                 (setf failure-reason "FailedDelete")
                 (setf active (stable-sort active
                                (lambda (a b)
                                  (let ((ra (pod-status-ready-p (cdr a))) (rb (pod-status-ready-p (cdr b))))
                                    (if (not (eql (not (null ra)) (not (null rb)))) (not ra)
                                        (string> (pod-name (car a)) (pod-name (car b))))))))
                 (loop for pair in active repeat (- delta)
                       for pod = (car pair)
                       do (delete-reconciled-pod reconciler (pod-namespace pod) (pod-name pod) :uid (pod-uid pod)))))
        (error (condition) (setf failure (princ-to-string condition)))))
    (let* ((active (replica-set-observations reconciler owner))
           (ready (count-if (lambda (pair) (pod-status-ready-p (cdr pair))) active))
           (available (count-if (lambda (pair) (workload-pod-available-p (cdr pair) (gethash "minReadySeconds" spec))) active))
           (labels (gethash "labels" (gethash "metadata" (gethash "template" spec) (core-object))))
           (fully-labeled (count-if (lambda (pair)
                                     (loop for key being the hash-keys of (or labels (core-object)) using (hash-value value)
                                           always (equal value (gethash key (gethash "labels" (workload-metadata (pod-to-object (car pair)))))))) active))
           (status (core-object "observedGeneration" (gethash "generation" (workload-metadata owner))
                                "replicas" (length active) "fullyLabeledReplicas" fully-labeled
                                "readyReplicas" ready "availableReplicas" available)))
      (when failure
        (let ((condition (workload-condition (gethash "conditions" (gethash "status" owner) #())
                                             "ReplicaFailure" "True" failure-reason failure)))
          ;; Replica conditions have no lastUpdateTime in their API schema.
          (remhash "lastUpdateTime" condition)
          (setf (gethash "conditions" status) (vector condition))))
      (update-workload-controller-status store (workload-owner-resource owner) owner status))))

(defun deployment-template (object)
  "Compare desired Pod templates independently of the generated rollout label."
  (let ((template (copy-core-object (gethash "template" (gethash "spec" object)))))
    (let ((labels (gethash "labels" (gethash "metadata" template)))) (when labels (remhash "pod-template-hash" labels)))
    template))

(defun deployment-revision (set)
  "Read a durable ReplicaSet revision annotation, tolerating malformed user values."
  (or (ignore-errors (parse-integer (gethash "deployment.kubernetes.io/revision"
                                           (gethash "annotations" (workload-metadata set)) "0") :junk-allowed nil)) 0))

(defun deployment-replica-sets (store owner &key claim)
  "Find exact deployment children and adopt unowned matching ReplicaSets."
  (let ((result nil) (metadata (workload-metadata owner)) (selector (gethash "selector" (gethash "spec" owner))))
    (dolist (set (list-core-resources store "replicasets" (gethash "namespace" metadata)))
      (cond ((gethash "deletionTimestamp" (workload-metadata set)) nil)
            ((and claim (workload-owned-p set owner)
                  (not (workload-selector-matches-p selector (gethash "labels" (workload-metadata set)))))
             (detach-workload-dependent store "replicasets" owner set))
            ((workload-owned-p set owner) (push set result))
            ((and claim (null (workload-controller-reference set))
                  (workload-selector-matches-p selector (gethash "labels" (workload-metadata set))))
             (with-store-lock (store)
               (when (workload-current-unlocked store "deployments" owner :generation t)
                 (let* ((current (get-core-resource-unlocked store "replicasets" (gethash "namespace" metadata)
                                                            (gethash "name" (workload-metadata set))))
                        (resources (copy-core-resource-index store)) (revision (1+ (pod-store-resource-revision store)))
                        (copy (copy-core-object current)))
                   (when (and (equal (gethash "uid" (workload-metadata current)) (gethash "uid" (workload-metadata set)))
                              (null (workload-controller-reference current))
                              (workload-selector-matches-p selector (gethash "labels" (workload-metadata current))))
                     (setf (gethash "ownerReferences" (workload-metadata copy))
                           (concatenate 'vector (gethash "ownerReferences" (workload-metadata copy) #())
                                        (vector (workload-owner-reference owner))))
                     (prepare-core-resource-metadata copy current revision)
                     (setf (gethash (core-resource-key "replicasets" (gethash "namespace" metadata)
                                                     (gethash "name" (workload-metadata copy))) resources) copy)
                     (commit-core-resources store resources revision)
                     (push copy result))))))))
    (sort result #'< :key #'deployment-revision)))

(defun deployment-ensure-current-set (store deployment sets)
  "Reuse a matching revision or create a real ReplicaSet for the current template."
  (let* ((template (deployment-template deployment))
         (current (find template sets :test #'workload-equal-p :key #'deployment-template))
         (revision (1+ (reduce #'max sets :key #'deployment-revision :initial-value 0)))
         (dmeta (workload-metadata deployment)) (spec (gethash "spec" deployment)))
    (unless current
      (let* ((collision (gethash "collisionCount" (gethash "status" deployment) 0))
             (fingerprint (if (zerop collision) template (core-object "template" template "collisionCount" collision)))
             (hash (string-downcase (subseq (octets-to-hex (ironclad:digest-sequence :sha256
                               (trivial-utf-8:string-to-utf-8-bytes (canonical-workload-json fingerprint)))) 0 10)))
             (name (format nil "~A-~A" (subseq (gethash "name" dmeta) 0 (min 242 (length (gethash "name" dmeta)))) hash))
             (selector (copy-core-object (gethash "selector" spec)))
             (labels (gethash "labels" (gethash "metadata" template)))
             (match-labels (gethash "matchLabels" selector (core-object))))
        (setf (gethash "pod-template-hash" labels) hash (gethash "pod-template-hash" match-labels) hash
              (gethash "matchLabels" selector) match-labels)
        (let ((input (core-object "apiVersion" "apps/v1" "kind" "ReplicaSet"
                                  "metadata" (core-object "name" name "labels" (copy-core-object labels)
                                               "ownerReferences" (vector (workload-owner-reference deployment))
                                               "annotations" (core-object "deployment.kubernetes.io/revision" (write-to-string revision)))
                                  "spec" (core-object "replicas" 0 "selector" selector "template" template
                                                       "minReadySeconds" (gethash "minReadySeconds" spec)))))
          ;; Verify the owner's identity and commit its child in one lock.
          (with-store-lock (store)
            (when (workload-current-unlocked store "deployments" deployment :generation t)
              (let* ((object (normalize-workload-resource "replicasets" input (gethash "namespace" dmeta) nil))
                     (key (core-resource-key "replicasets" (gethash "namespace" dmeta) name))
                     (resources (copy-core-resource-index store)) (version (1+ (pod-store-resource-revision store))))
                (when (gethash key resources)
                  (let* ((live (workload-current-unlocked store "deployments" deployment :generation t))
                         (copy (copy-core-object live)) (status (gethash "status" copy (core-object))))
                    (setf (gethash "collisionCount" status) (1+ collision) (gethash "status" copy) status)
                    (prepare-core-resource-metadata copy live version)
                    (setf (gethash (core-resource-key "deployments" (gethash "namespace" dmeta) (gethash "name" dmeta)) resources) copy)
                    (commit-core-resources store resources version))
                  (core-resource-error 409 "Conflict" "ReplicaSet template hash name collision; next pass uses a new collision count"))
                (prepare-core-resource-metadata object nil version)
                (prepare-workload-write "replicasets" object nil)
                (setf (gethash key resources) object)
                (commit-core-resources store resources version)
                (setf current object)))))))
    (when current
      (unless (= (gethash "minReadySeconds" spec) (gethash "minReadySeconds" (gethash "spec" current)))
        (setf current (update-owned-workload store "replicasets" current
                        (lambda (object) (setf (gethash "minReadySeconds" (gethash "spec" object))
                                               (gethash "minReadySeconds" spec)) object))))
      (when (< (deployment-revision current) (max 1 (1- revision)))
        (setf current (update-owned-workload store "replicasets" current
                        (lambda (object)
                          (let ((annotations (gethash "annotations" (workload-metadata object) (core-object))))
                            (setf (gethash "deployment.kubernetes.io/revision" annotations) (write-to-string revision)
                                  (gethash "annotations" (workload-metadata object)) annotations)) object))))
      (unless (equal (write-to-string (deployment-revision current))
                     (gethash "deployment.kubernetes.io/revision" (gethash "annotations" dmeta (core-object))))
        (update-owned-workload store "deployments" deployment
          (lambda (object)
            (let ((annotations (gethash "annotations" (workload-metadata object) (core-object))))
              (setf (gethash "deployment.kubernetes.io/revision" annotations) (write-to-string (deployment-revision current)))
              (setf (gethash "annotations" (workload-metadata object)) annotations)) object))))
    current))

(defun deployment-scale-set (store set count desired maximum)
  "Change desired replicas and scaling annotations without rewriting stable status."
  (let* ((metadata (workload-metadata set)) (annotations (gethash "annotations" metadata (core-object))))
    (if (and (= count (gethash "replicas" (gethash "spec" set)))
             (equal (write-to-string desired) (gethash "deployment.kubernetes.io/desired-replicas" annotations))
             (equal (write-to-string maximum) (gethash "deployment.kubernetes.io/max-replicas" annotations))) set
        (update-owned-workload store "replicasets" set
          (lambda (object)
            (setf (gethash "replicas" (gethash "spec" object)) count)
            (let ((annotations (gethash "annotations" (workload-metadata object) (core-object))))
              (setf (gethash "deployment.kubernetes.io/desired-replicas" annotations) (write-to-string desired)
                    (gethash "deployment.kubernetes.io/max-replicas" annotations) (write-to-string maximum)
                    (gethash "annotations" (workload-metadata object)) annotations)) object)))))

(defun deployment-old-pods-exist-p (reconciler sets)
  "Recreate waits for the old workload's processes, including terminating Pods."
  (some (lambda (set)
          (some (lambda (pod) (not (member (gethash "phase" (workload-pod-status reconciler pod))
                                         '("Succeeded" "Failed") :test #'equal)))
                (replica-set-pods reconciler set))) sets))

(defun deployment-scaling-event-p (sets desired)
  "Detect a desired-size change using the last durable ReplicaSet scaling annotations."
  (some (lambda (set)
          (let ((before (ignore-errors
                          (parse-integer (gethash "deployment.kubernetes.io/desired-replicas"
                                                  (gethash "annotations" (workload-metadata set))) :junk-allowed nil))))
            (and (plusp (gethash "replicas" (gethash "spec" set))) before (/= desired before))))
        sets))

(defun deployment-proportional-scale (store deployment current sets desired surge)
  "Distribute a scaling event across active revisions using their pre-scale maximum annotation."
  (let* ((active (remove-if-not (lambda (set) (plusp (gethash "replicas" (gethash "spec" set)))) sets))
         (maximum (+ desired surge)))
    (cond
      ((<= (length active) 1)
       (deployment-scale-set store (or (first active) current) desired desired maximum))
      ((and (= desired (gethash "replicas" (gethash "spec" current)))
            (>= (gethash "availableReplicas" (gethash "status" current) 0) desired))
       (dolist (set sets)
         (deployment-scale-set store set (if (equal (gethash "uid" (workload-metadata current))
                                                    (gethash "uid" (workload-metadata set))) desired 0) desired maximum)))
      (t
       (let* ((total (reduce #'+ active :key (lambda (set) (gethash "replicas" (gethash "spec" set))) :initial-value 0))
              (allowed (if (zerop desired) 0 maximum)) (delta (- allowed total)) (allocated 0)
              (sizes (make-hash-table :test #'equal)))
         (setf active
               (stable-sort active
                 (lambda (left right)
                   (let ((l (gethash "replicas" (gethash "spec" left))) (r (gethash "replicas" (gethash "spec" right))))
                     (if (/= l r) (> l r)
                         (if (minusp delta) (< (deployment-revision left) (deployment-revision right))
                             (> (deployment-revision left) (deployment-revision right))))))))
         (dolist (set active)
           (let* ((count (gethash "replicas" (gethash "spec" set)))
                  (before (or (ignore-errors (parse-integer (gethash "deployment.kubernetes.io/max-replicas"
                                                                     (gethash "annotations" (workload-metadata set))) :junk-allowed nil)) 0))
                  (denominator (if (plusp before) before (gethash "replicas" (gethash "status" deployment) 0)))
                  (fraction (cond ((zerop desired) (- count))
                                  ((plusp denominator) (- (floor (+ (* count maximum) (/ denominator 2)) denominator) count))
                                  (t 0)))
                  (portion (cond ((= delta allocated) 0)
                                 ((plusp delta) (min fraction (- delta allocated)))
                                 (t (max fraction (- delta allocated))))))
             (setf (gethash (gethash "uid" (workload-metadata set)) sizes) (+ count portion))
             (incf allocated portion)))
         (let* ((first (first active)) (uid (gethash "uid" (workload-metadata first))))
           (incf (gethash uid sizes) (- delta allocated)))
         (dolist (set active)
           (deployment-scale-set store set (max 0 (gethash (gethash "uid" (workload-metadata set)) sizes)) desired maximum)))))))

(defun reconcile-deployment (reconciler deployment)
  "Drive bounded rolling/recreate rollout and publish observed aggregate status."
  (let* ((store (reconciler-store reconciler)) (spec (gethash "spec" deployment))
         (desired (gethash "replicas" spec)) (sets (deployment-replica-sets store deployment :claim t))
         (paused (eq t (gethash "paused" spec)))
         (current (if paused (car (last sets)) (deployment-ensure-current-set store deployment sets))))
    (when current
      (setf sets (deployment-replica-sets store deployment))
      (let* ((uid (gethash "uid" (workload-metadata current)))
             (old (remove uid sets :test #'equal :key (lambda (set) (gethash "uid" (workload-metadata set)))))
             (strategy (gethash "strategy" spec)) (recreate (equal "Recreate" (gethash "type" strategy)))
             (rolling (gethash "rollingUpdate" strategy (core-object)))
             (surge (if recreate 0 (workload-rollout-count (gethash "maxSurge" rolling) desired :round-up t)))
             (unavailable (if recreate 0 (min desired (workload-rollout-count (gethash "maxUnavailable" rolling) desired)))))
        (when (and (not recreate) (plusp desired) (zerop surge) (zerop unavailable))
          (setf unavailable 1))
        (cond
          ((or paused (and (not recreate) (deployment-scaling-event-p sets desired)))
           (deployment-proportional-scale store deployment current sets desired surge))
          (recreate
           (dolist (set old) (deployment-scale-set store set 0 desired desired))
           (unless (deployment-old-pods-exist-p reconciler old) (deployment-scale-set store current desired desired desired)))
          (t
           (let* ((old-total (reduce #'+ old :key (lambda (set) (gethash "replicas" (gethash "spec" set))) :initial-value 0))
                  (target (min desired (max 0 (- (+ desired surge) old-total)))))
             (setf current (deployment-scale-set store current target desired (+ desired surge)))
             (let* ((available (reduce #'+ sets :key (lambda (set) (gethash "availableReplicas" (gethash "status" set) 0)) :initial-value 0))
                    (budget (max 0 (- available (- desired unavailable))))
                    (maximum-down (max 0 (- (+ old-total target) (- desired unavailable)
                                               (max 0 (- target (gethash "availableReplicas" (gethash "status" current) 0)))))))
               (dolist (set old)
                 (let* ((count (gethash "replicas" (gethash "spec" set)))
                        (ready (min count (gethash "availableReplicas" (gethash "status" set) 0)))
                        (remove (min count maximum-down (+ (- count ready) budget)))
                        (ready-removed (max 0 (- remove (- count ready)))))
                   (when (plusp remove) (deployment-scale-set store set (- count remove) desired (+ desired surge)))
                   (decf maximum-down remove)
                   (decf budget ready-removed)))))))
        (deployment-publish-status reconciler deployment current unavailable paused)
        (deployment-clean-history reconciler deployment current)))
    (when (and paused (null current))
      (deployment-publish-status reconciler deployment nil 0 t))))

(defun deployment-publish-status (reconciler deployment current unavailable paused)
  "Derive deployment status from the actual child ReplicaSet observations."
  (let* ((store (reconciler-store reconciler)) (sets (deployment-replica-sets store deployment))
         (spec (gethash "spec" deployment)) (desired (gethash "replicas" spec))
         (prior (gethash "status" deployment (core-object))) (previous (gethash "conditions" prior #()))
         (uid (and current (gethash "uid" (workload-metadata current))))
         (new (find uid sets :test #'equal :key (lambda (set) (gethash "uid" (workload-metadata set)))))
         (replicas (reduce #'+ sets :key (lambda (set) (gethash "replicas" (gethash "status" set) 0)) :initial-value 0))
         (ready (reduce #'+ sets :key (lambda (set) (gethash "readyReplicas" (gethash "status" set) 0)) :initial-value 0))
         (available (reduce #'+ sets :key (lambda (set) (gethash "availableReplicas" (gethash "status" set) 0)) :initial-value 0))
         (updated (if new (gethash "replicas" (gethash "status" new) 0) 0))
         (complete (and (= updated desired) (= replicas desired) (>= available desired)))
         (progress (or (/= updated (gethash "updatedReplicas" prior -1))
                       (> available (gethash "availableReplicas" prior -1))
                       (< replicas (gethash "replicas" prior 2147483647))
                       (not (eql (gethash "generation" (workload-metadata deployment)) (gethash "observedGeneration" prior)))))
         (old-progressing (find "Progressing" previous :test #'equal :key (lambda (condition) (gethash "type" condition))))
         (progressing (if (and old-progressing (not progress) (not complete) (not paused)
                               (equal "ProgressDeadlineExceeded" (gethash "reason" old-progressing)))
                          (copy-core-object old-progressing)
                          (workload-condition previous "Progressing" (if paused "Unknown" "True")
                        (cond (paused "DeploymentPaused") (complete "NewReplicaSetAvailable") (t "ReplicaSetUpdated"))
                        (if complete "The deployment's replicas are available" "Reconciling the deployment's ReplicaSets") :progress progress)))
         (status (core-object "observedGeneration" (gethash "generation" (workload-metadata deployment))
                              "replicas" replicas "updatedReplicas" updated "readyReplicas" ready "availableReplicas" available
                              "unavailableReplicas" (max 0 (- desired available)))))
    (when (nth-value 1 (gethash "collisionCount" prior))
      (setf (gethash "collisionCount" status) (gethash "collisionCount" prior)))
    (let ((time (ignore-errors (pod-deletion-time (gethash "lastUpdateTime" progressing)))))
      (when (and (not paused) (not complete) time
                 (> (funcall *workload-clock*) (+ time (gethash "progressDeadlineSeconds" spec))))
        (setf progressing (workload-condition previous "Progressing" "False" "ProgressDeadlineExceeded"
                                              "The deployment exceeded its progress deadline"))))
    (let ((conditions (list (workload-condition previous "Available" (if (>= available (- desired unavailable)) "True" "False")
                            (if (>= available (- desired unavailable)) "MinimumReplicasAvailable" "MinimumReplicasUnavailable")
                            "Availability is derived from ready child Pods") progressing)))
      (dolist (set sets)
        (let ((failure (find "ReplicaFailure" (gethash "conditions" (gethash "status" set) #())
                             :test #'equal :key (lambda (condition) (gethash "type" condition)))))
          (when failure (push (copy-core-object failure) conditions) (return))))
      (setf (gethash "conditions" status) (coerce conditions 'vector)))
    (update-workload-controller-status store "deployments" deployment status)))

(defun deployment-clean-history (reconciler deployment current)
  "Delete excess zero-replica old revisions only after rollout completion."
  (let* ((store (reconciler-store reconciler))
         (live (get-core-resource store "deployments" (gethash "namespace" (workload-metadata deployment))
                                  (gethash "name" (workload-metadata deployment))))
         (status (gethash "status" live)) (desired (gethash "replicas" (gethash "spec" live)))
         (sets (deployment-replica-sets store deployment))
         (old (remove (gethash "uid" (workload-metadata current)) sets :test #'equal
                      :key (lambda (set) (gethash "uid" (workload-metadata set))))))
    (when (and (= desired (gethash "updatedReplicas" status 0)) (>= (gethash "availableReplicas" status 0) desired)
               (= desired (gethash "replicas" status 0)))
      (let ((excess (- (length old) (gethash "revisionHistoryLimit" (gethash "spec" live)))))
        (dolist (set old)
          (when (and (plusp excess) (zerop (gethash "replicas" (gethash "spec" set)))
                     (not (deployment-old-pods-exist-p reconciler (list set))))
            (let ((metadata (workload-metadata set)))
              (delete-core-resource store "replicasets" (gethash "namespace" metadata) (gethash "name" metadata)
                                    :uid (gethash "uid" metadata)))
            (decf excess)))))))

(defun reconcile-workloads (reconciler)
  "Run authoritative workload controllers; node agents never invoke this pass."
  (let ((store (reconciler-store reconciler)))
    (bt:with-lock-held ((pod-store-workload-lock store))
      (process-workload-deletions reconciler)
      (reconcile-jobs reconciler)
      (reconcile-disruption-budgets reconciler)
      (reconcile-cronjobs reconciler)
      (dolist (resource '("deployments" "replicasets" "replicationcontrollers" "daemonsets" "statefulsets"))
        (dolist (object (list-core-resources store resource))
          (handler-case
              (unless (gethash "deletionTimestamp" (workload-metadata object))
                (cond ((equal resource "deployments") (reconcile-deployment reconciler object))
                      ((equal resource "daemonsets") (reconcile-daemonset reconciler object))
                      ((equal resource "statefulsets") (reconcile-statefulset reconciler object))
                      (t (reconcile-replica-set reconciler object))))
            (kubernetes-error (condition)
              (unless (member (kubernetes-error-status-code condition) '(404 409))
                (format *error-output* "gr8s ~A controller: ~A~%" resource condition)))
            (error (condition) (format *error-output* "gr8s ~A controller: ~A~%" resource condition)))))))
  reconciler)
