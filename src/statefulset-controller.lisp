;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Reconcile StatefulSets with the semantics of the Kubernetes controller: stable
;;;; ordinal names and hostnames, one PersistentVolumeClaim per template and ordinal,
;;;; ordered or parallel Pod management, and rolling updates in reverse ordinal order
;;;; bounded by a partition. Each template is a ControllerRevision, so a rollback
;;;; returns to the earlier revision rather than creating a new one.

(in-package #:gr8s)

(defparameter +statefulset-pod-name-label+ "statefulset.kubernetes.io/pod-name"
  "Label holding a stateful Pod's own name, which Services can select one Pod by.")

(defparameter +statefulset-pod-index-label+ "apps.kubernetes.io/pod-index"
  "Label holding a stateful Pod's ordinal.")

(defun statefulset-start-ordinal (spec)
  "Return the first ordinal SPEC asks for."
  (let ((ordinals (gethash "ordinals" spec)))
    (if (hash-table-p ordinals) (gethash "start" ordinals 0) 0)))

(defun statefulset-pod-ordinal (set name)
  "Return the ordinal in Pod NAME if it follows SET's naming, or NIL."
  (let* ((prefix (concatenate 'string (gethash "name" (workload-metadata set)) "-"))
         (suffix (and (uiop:string-prefix-p prefix name) (subseq name (length prefix)))))
    (when (and suffix (plusp (length suffix)) (every #'digit-char-p suffix)
               (or (= 1 (length suffix)) (char/= #\0 (char suffix 0))))
      (parse-integer suffix))))

(defun statefulset-claim-name (set template ordinal)
  "Return the stable claim name for one volume claim TEMPLATE and ORDINAL of SET."
  (format nil "~A-~A-~D" (gethash "name" (gethash "metadata" template))
          (gethash "name" (workload-metadata set)) ordinal))

(defun statefulset-claim-object (set template ordinal)
  "Build the PersistentVolumeClaim one claim TEMPLATE describes for ORDINAL of SET."
  (let* ((source (gethash "metadata" template)) (metadata (core-object))
         (selector (gethash "selector" (gethash "spec" set)))
         (labels (copy-core-object (gethash "labels" source (core-object))))
         (retention (gethash "persistentVolumeClaimRetentionPolicy" (gethash "spec" set)))
         (spec (copy-core-object (gethash "spec" template))))
    (maphash (lambda (key value) (setf (gethash key labels) value)) (gethash "matchLabels" selector (core-object)))
    (setf (gethash "name" metadata) (statefulset-claim-name set template ordinal)
          (gethash "namespace" metadata) (gethash "namespace" (workload-metadata set))
          (gethash "labels" metadata) labels)
    (when (gethash "annotations" source)
      (setf (gethash "annotations" metadata) (copy-core-object (gethash "annotations" source))))
    ;; Collecting a claim when its set goes is what a garbage collector owner reference is for.
    (when (and (gethash "uid" (workload-metadata set)) (equal "Delete" (gethash "whenDeleted" retention)))
      (let ((reference (workload-owner-reference set)))
        (setf (gethash "controller" reference) nil
              (gethash "ownerReferences" metadata) (vector reference))))
    (core-object "apiVersion" "v1" "kind" "PersistentVolumeClaim" "metadata" metadata "spec" spec)))

(defun statefulset-revision-template (revision)
  "Return the Pod template a ControllerRevision records."
  (let ((template (copy-core-object (gethash "template" (gethash "spec" (gethash "data" revision))))))
    (remhash "$patch" template)
    template))

(defun statefulset-pod-object (set template ordinal revision-name)
  "Build SET's Pod at ORDINAL from TEMPLATE, with its stable identity and claims."
  (let* ((spec (gethash "spec" set)) (name (format nil "~A-~D" (gethash "name" (workload-metadata set)) ordinal))
         (source (gethash "metadata" template (core-object))) (metadata (core-object))
         (labels (copy-core-object (gethash "labels" source (core-object))))
         (pod-spec (copy-core-object (gethash "spec" template)))
         (service (gethash "serviceName" spec ""))
         (claims (gethash "volumeClaimTemplates" spec #())))
    (dolist (key '("annotations" "finalizers"))
      (when (gethash key source) (setf (gethash key metadata) (copy-core-object (gethash key source)))))
    (setf (gethash "controller-revision-hash" labels) revision-name
          (gethash +statefulset-pod-name-label+ labels) name
          (gethash +statefulset-pod-index-label+ labels) (write-to-string ordinal)
          (gethash "name" metadata) name
          (gethash "namespace" metadata) (gethash "namespace" (workload-metadata set))
          (gethash "labels" metadata) labels
          (gethash "hostname" pod-spec) name)
    (when (gethash "uid" (workload-metadata set))
      (setf (gethash "ownerReferences" metadata) (vector (workload-owner-reference set))))
    (when (plusp (length service)) (setf (gethash "subdomain" pod-spec) service))
    (when (plusp (length claims))
      ;; A claim replaces a template volume of the same name, as upstream does.
      (let ((volumes (remove-if (lambda (volume)
                                  (find (gethash "name" volume) claims :test #'equal
                                        :key (lambda (claim) (gethash "name" (gethash "metadata" claim)))))
                                (gethash "volumes" pod-spec #()))))
        (setf (gethash "volumes" pod-spec)
              (concatenate 'vector volumes
                           (map 'vector (lambda (claim)
                                          (core-object "name" (gethash "name" (gethash "metadata" claim))
                                                       "persistentVolumeClaim"
                                                       (core-object "claimName" (statefulset-claim-name set claim ordinal))))
                                claims)))))
    (core-object "apiVersion" "v1" "kind" "Pod" "metadata" metadata "spec" pod-spec)))

(defun statefulset-revisions (store set)
  "Return SET's revision history, oldest first, and its revision for the current template.
A template equal to an older revision makes that revision the newest again, which is a rollback."
  (let* ((revisions (daemonset-revisions store set)) (data (daemonset-revision-data set))
         (matching (remove-if-not (lambda (revision) (workload-equal-p (gethash "data" revision) data)) revisions))
         (newest (reduce #'max revisions :key (lambda (revision) (gethash "revision" revision)) :initial-value 0))
         (match (car (last matching)))
         (update (cond ((null match) (create-daemonset-revision store set data (1+ newest)))
                       ((= (gethash "revision" match) newest) match)
                       (t (update-owned-workload store "controllerrevisions" match
                            (lambda (object) (setf (gethash "revision" object) (1+ newest)) object))))))
    (values (sort (cons update (remove (gethash "uid" (workload-metadata update)) revisions
                                       :test #'equal :key (lambda (revision) (gethash "uid" (workload-metadata revision)))))
                  #'< :key (lambda (revision) (gethash "revision" revision)))
            update)))

(defun statefulset-member-pods (reconciler set)
  "Return (ordinal pod . status) for SET's Pods, adopting matching orphans and releasing mismatches."
  (let* ((store (reconciler-store reconciler)) (selector (gethash "selector" (gethash "spec" set))) (result nil))
    (dolist (pod (list-pods store (gethash "namespace" (workload-metadata set))))
      (let* ((object (pod-to-object pod)) (owned (workload-owned-p object set))
             (matches (workload-selector-matches-p selector (gethash "labels" (workload-metadata object))))
             (ordinal (statefulset-pod-ordinal set (pod-name pod))))
        (cond
          ((and owned (not matches)) (change-controller-pod-owner store set pod nil :resource "statefulsets"))
          ((and owned ordinal) (push (list* ordinal pod (workload-pod-status reconciler pod)) result))
          ((and matches ordinal (not (deletion-requested-p pod)) (null (workload-controller-reference object)))
           (let ((adopted (change-controller-pod-owner store set pod t :resource "statefulsets")))
             (when adopted (push (list* ordinal adopted (workload-pod-status reconciler adopted)) result)))))))
    (sort result #'< :key #'first)))

(defun statefulset-member-pod (member)
  "Return a member's Pod."
  (second member))

(defun statefulset-member-status (member)
  "Return a member's observed status."
  (cddr member))

(defun statefulset-member-healthy-p (member)
  "Return whether a member is running, ready and not being deleted."
  (and member (not (deletion-requested-p (statefulset-member-pod member)))
       (equal "Running" (gethash "phase" (statefulset-member-status member)))
       (pod-status-ready-p (statefulset-member-status member))))

(defun statefulset-member-revision (member)
  "Return the revision name a member's Pod was created from."
  (gethash "controller-revision-hash" (gethash "labels" (workload-metadata (pod-to-object (statefulset-member-pod member)))) ""))

(defun statefulset-update-minimum (spec)
  "Return the lowest ordinal offset a rolling update may touch, which is its partition."
  (let ((rolling (gethash "rollingUpdate" (gethash "updateStrategy" spec))))
    (if (hash-table-p rolling) (gethash "partition" rolling 0) 0)))

(defun statefulset-ensure-claims (store set ordinal)
  "Create ORDINAL's missing claims and return true when none of them is being deleted."
  (let ((namespace (gethash "namespace" (workload-metadata set))) (usable t))
    (loop for template across (gethash "volumeClaimTemplates" (gethash "spec" set) #())
          for name = (statefulset-claim-name set template ordinal)
          do (let ((existing (with-store-lock (store)
                               (gethash (core-resource-key "persistentvolumeclaims" namespace name)
                                        (pod-store-resources store)))))
               (cond ((null existing)
                      (create-core-resource store "persistentvolumeclaims"
                                            (statefulset-claim-object set template ordinal) namespace))
                     ((gethash "deletionTimestamp" (gethash "metadata" existing)) (setf usable nil)))))
    usable))

(defun create-statefulset-pod (store set template ordinal revision-name)
  "Create SET's Pod at ORDINAL unless SET changed since it was read, after its claims exist."
  (when (statefulset-ensure-claims store set ordinal)
    (let ((pod (admit-in-cluster-pod store (parse-pod (statefulset-pod-object set template ordinal revision-name)))))
      (with-store-lock (store)
        (when (workload-current-unlocked store "statefulsets" set :generation t)
          (create-pod-unlocked store pod))))))

(defun statefulset-delete-pod (reconciler member)
  "Start deleting one exact member Pod, tolerating one that is already gone."
  (let ((pod (statefulset-member-pod member)))
    (handler-case (delete-reconciled-pod reconciler (pod-namespace pod) (pod-name pod) :uid (pod-uid pod))
      (kubernetes-error (condition)
        (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition))))))

(defun statefulset-template-for-ordinal (set current update ordinal)
  "Return the revision a new Pod at ORDINAL takes: below the partition it stays at CURRENT."
  (let ((spec (gethash "spec" set)))
    (if (and (equal "RollingUpdate" (gethash "type" (gethash "updateStrategy" spec)))
             (< ordinal (+ (statefulset-start-ordinal spec) (statefulset-update-minimum spec))))
        current update)))

(defun statefulset-repair-identity (store member)
  "Restore the identity labels of a member Pod a client removed them from."
  (let* ((pod (statefulset-member-pod member)) (object (copy-core-object (pod-to-object pod)))
         (labels (gethash "labels" (workload-metadata object)))
         (name (write-to-string (first member))))
    (unless (and (equal (pod-name pod) (gethash +statefulset-pod-name-label+ labels))
                 (equal name (gethash +statefulset-pod-index-label+ labels)))
      (setf (gethash +statefulset-pod-name-label+ labels) (pod-name pod)
            (gethash +statefulset-pod-index-label+ labels) name)
      (handler-case (update-pod store (parse-pod object) (pod-resource-version pod))
        (kubernetes-error (condition)
          (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))

(defun statefulset-scale-up (reconciler set current update members)
  "Bring the wanted ordinals into being; return true when the ordered policy must stop this pass."
  (let* ((store (reconciler-store reconciler)) (spec (gethash "spec" set))
         (ordered (equal "OrderedReady" (gethash "podManagementPolicy" spec)))
         (minimum (gethash "minReadySeconds" spec)) (start (statefulset-start-ordinal spec)))
    (loop for ordinal from start below (+ start (gethash "replicas" spec))
          for member = (assoc ordinal members)
          do (cond
               ((null member)
                (let ((revision (statefulset-template-for-ordinal set current update ordinal)))
                  (create-statefulset-pod store set (statefulset-revision-template revision) ordinal
                                          (gethash "name" (workload-metadata revision))))
                (when ordered (return t)))
               ((deletion-requested-p (statefulset-member-pod member))
                (when ordered (return t)))
               ((member (gethash "phase" (statefulset-member-status member)) '("Failed" "Succeeded") :test #'equal)
                (statefulset-delete-pod reconciler member)
                (when ordered (return t)))
               (t
                (statefulset-repair-identity store member)
                (when (and ordered (or (not (statefulset-member-healthy-p member))
                                       (not (workload-pod-available-p (statefulset-member-status member) minimum))))
                  (return t))))
          finally (return nil))))

(defun statefulset-scale-down (reconciler set members)
  "Delete ordinals outside the wanted range, highest first; return true when the ordered policy must stop."
  (let* ((spec (gethash "spec" set)) (start (statefulset-start-ordinal spec))
         (end (+ start (gethash "replicas" spec)))
         (ordered (equal "OrderedReady" (gethash "podManagementPolicy" spec)))
         (condemned (remove-if (lambda (member) (and (<= start (first member)) (< (first member) end))) members))
         (first-unhealthy (find-if-not #'statefulset-member-healthy-p members)))
    (dolist (member (reverse condemned) nil)
      (cond
        ((deletion-requested-p (statefulset-member-pod member))
         (when ordered (return t)))
        ((and ordered (not (statefulset-member-healthy-p member)) (not (eq member first-unhealthy)))
         (return t))
        (t (statefulset-delete-pod reconciler member)
           (when ordered (return t)))))))

(defun statefulset-roll (reconciler set update members)
  "Replace one out-of-date Pod at a time from the highest ordinal down to the partition."
  (let* ((spec (gethash "spec" set)) (start (statefulset-start-ordinal spec))
         (lowest (+ start (statefulset-update-minimum spec))) (name (gethash "name" (workload-metadata update))))
    (when (equal "RollingUpdate" (gethash "type" (gethash "updateStrategy" spec)))
      (loop for ordinal from (1- (+ start (gethash "replicas" spec))) downto lowest
            for member = (assoc ordinal members)
            do (cond
                 ((null member) (return))
                 ((and (not (equal name (statefulset-member-revision member)))
                       (not (deletion-requested-p (statefulset-member-pod member))))
                  (statefulset-delete-pod reconciler member)
                  (return))
                 ((not (statefulset-member-healthy-p member)) (return)))))))

(defun statefulset-delete-scaled-claims (store set members)
  "Delete the claims of ordinals scaled away once their Pods are gone, when retention asks for it."
  (let* ((spec (gethash "spec" set)) (start (statefulset-start-ordinal spec)) (end (+ start (gethash "replicas" spec))))
    (when (and (equal "Delete" (gethash "whenScaled" (gethash "persistentVolumeClaimRetentionPolicy" spec)))
               (plusp (length (gethash "volumeClaimTemplates" spec #()))))
      (let ((namespace (gethash "namespace" (workload-metadata set))))
        (dolist (claim (list-core-resources store "persistentvolumeclaims" namespace))
          (let* ((name (gethash "name" (gethash "metadata" claim)))
                 (ordinal (loop for template across (gethash "volumeClaimTemplates" spec)
                                for prefix = (format nil "~A-~A-" (gethash "name" (gethash "metadata" template))
                                                     (gethash "name" (workload-metadata set)))
                                when (uiop:string-prefix-p prefix name)
                                  do (let ((suffix (subseq name (length prefix))))
                                       (when (and (plusp (length suffix)) (every #'digit-char-p suffix))
                                         (return (parse-integer suffix)))))))
            (when (and ordinal (or (< ordinal start) (>= ordinal end)) (not (assoc ordinal members)))
              (handler-case (delete-core-resource store "persistentvolumeclaims" namespace name
                                                  :uid (gethash "uid" (gethash "metadata" claim)))
                (kubernetes-error (condition)
                  (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))))))))

(defun statefulset-truncate-history (store set revisions current update members)
  "Delete the oldest revisions beyond revisionHistoryLimit that nothing still uses."
  (let* ((live (append (list (gethash "name" (workload-metadata current)) (gethash "name" (workload-metadata update)))
                       (mapcar #'statefulset-member-revision members)))
         (old (remove-if (lambda (revision) (member (gethash "name" (workload-metadata revision)) live :test #'equal)) revisions))
         (excess (- (length old) (gethash "revisionHistoryLimit" (gethash "spec" set)))))
    (dolist (revision old)
      (when (plusp excess)
        (let ((metadata (workload-metadata revision)))
          (delete-core-resource store "controllerrevisions" (gethash "namespace" metadata)
                                (gethash "name" metadata) :uid (gethash "uid" metadata)))
        (decf excess)))))

(defun publish-statefulset-status (reconciler set current update)
  "Report what SET's Pods actually show, and finish a rollout that has reached every replica."
  (let* ((members (statefulset-member-pods reconciler set)) (spec (gethash "spec" set))
         (minimum (gethash "minReadySeconds" spec)) (prior (gethash "status" set (core-object)))
         (current-name (gethash "name" (workload-metadata current)))
         (update-name (gethash "name" (workload-metadata update)))
         (replicas (length members)) (ready 0) (available 0) (on-current 0) (on-update 0))
    (dolist (member members)
      (when (statefulset-member-healthy-p member)
        (incf ready)
        (when (workload-pod-available-p (statefulset-member-status member) minimum) (incf available)))
      (unless (deletion-requested-p (statefulset-member-pod member))
        (let ((revision (statefulset-member-revision member)))
          (when (equal revision current-name) (incf on-current))
          (when (equal revision update-name) (incf on-update)))))
    (when (and (equal "RollingUpdate" (gethash "type" (gethash "updateStrategy" spec)))
               (= on-update replicas (gethash "replicas" spec)) (= ready replicas))
      (setf current-name update-name on-current on-update))
    (let ((status (core-object "observedGeneration" (gethash "generation" (workload-metadata set))
                               "replicas" replicas "readyReplicas" ready "availableReplicas" available
                               "currentReplicas" on-current "updatedReplicas" on-update
                               "currentRevision" current-name "updateRevision" update-name)))
      (dolist (field '("collisionCount" "conditions"))
        (when (nth-value 1 (gethash field prior)) (setf (gethash field status) (gethash field prior))))
      (update-workload-controller-status (reconciler-store reconciler) "statefulsets" set status))))

(defun reconcile-statefulset (reconciler set)
  "Advance SET one step: scale up, then scale down, then roll, stopping where its policy says to."
  (let ((store (reconciler-store reconciler)))
    (multiple-value-bind (revisions update) (statefulset-revisions store set)
      (let* ((named (gethash "currentRevision" (gethash "status" set (core-object))))
             (current (or (find named revisions :test #'equal
                                :key (lambda (revision) (gethash "name" (workload-metadata revision))))
                          update))
             (members (statefulset-member-pods reconciler set)))
        (unless (or (statefulset-scale-up reconciler set current update members)
                    (statefulset-scale-down reconciler set members))
          (statefulset-roll reconciler set update members))
        (statefulset-delete-scaled-claims store set members)
        (publish-statefulset-status reconciler set current update)
        (statefulset-truncate-history store set revisions current update (statefulset-member-pods reconciler set))))))
