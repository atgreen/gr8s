;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Reconcile DaemonSets: one Pod on each eligible node, ControllerRevision
;;;; history, RollingUpdate and OnDelete strategies and observed status. A
;;;; revision's data is the exact JSON a typed client derives from the DaemonSet,
;;;; because kubectl and upstream clients compare it byte for byte.

(in-package #:gr8s.controllers)

(defparameter +controller-revision-hash-label+ "controller-revision-hash"
  "Label tying a daemon Pod and a ControllerRevision to one template revision.")

(defun go-json-empty-p (value)
  "Return whether Go's omitempty drops VALUE, a stored JSON scalar or collection."
  (or (member value '(nil null))
      (equal value "")
      (and (numberp value) (zerop value))
      (and (vectorp value) (not (stringp value)) (zerop (length value)))))

(defun go-json-message-field (message key)
  "Find KEY's field definition in protobuf MESSAGE, looking through inlined messages."
  (let ((descriptor (gethash message (gethash "messages" *podtemplate-schema*))))
    (when descriptor
      (loop for definition being the hash-values of descriptor
            thereis (cond ((gethash "inline" definition)
                           (go-json-message-field (gethash "type" definition) key))
                          ((equal key (gethash "name" definition)) definition))))))

(defun go-json-sorted (value)
  "Copy a JSON VALUE with every object's keys inserted in sorted order."
  (cond ((hash-table-p value)
         (let ((result (core-object)))
           (dolist (key (sort (loop for key being the hash-keys of value collect key) #'string<) result)
             (setf (gethash key result) (go-json-sorted (gethash key value))))))
        ((and (vectorp value) (not (stringp value))) (map 'vector #'go-json-sorted value))
        (t value)))

(defun go-json-view (value message)
  "Rewrite VALUE, an object of protobuf MESSAGE, as a typed Go client would marshal it.
Keys are sorted, unset and omitempty zero values vanish, and pointers to empty objects stay."
  (unless (and (hash-table-p value) (gethash message (gethash "messages" *podtemplate-schema*)))
    (return-from go-json-view (go-json-sorted value)))
  (let ((result (core-object)) (keys (loop for key being the hash-keys of value collect key)))
    ;; A Container's resources is a non-pointer struct, which omitempty keeps.
    (when (and (equal message "k8s.io.api.core.v1.Container") (not (gethash "resources" value)))
      (setf (gethash "resources" value) (core-object))
      (pushnew "resources" keys :test #'equal))
    (dolist (key (sort keys #'string<) result)
      (let* ((field (gethash key value)) (definition (go-json-message-field message key))
             (type (and definition (gethash "type" definition))))
        (cond
          ((null definition) (unless (eq field 'null) (setf (gethash key result) (go-json-sorted field))))
          ((eq field 'null) nil)
          ((gethash "mapKey" definition)
           (when (plusp (hash-table-count field))
             (let ((map (core-object)))
               (dolist (name (sort (loop for name being the hash-keys of field collect name) #'string<))
                 (setf (gethash name map) (go-json-view (gethash name field) type)))
               (setf (gethash key result) map))))
          ((gethash "repeated" definition)
           (unless (go-json-empty-p field)
             (setf (gethash key result) (map 'vector (lambda (item) (go-json-view item type)) field))))
          ((and (gethash "omitEmpty" definition) (go-json-empty-p field)) nil)
          ;; Typed requests carry ObjectMeta's zero values, which the pinned wire
          ;; schema does not mark. All but one of its scalars are omitempty.
          ((and (equal message "k8s.io.apimachinery.pkg.apis.meta.v1.ObjectMeta")
                (not (equal key "deletionGracePeriodSeconds")) (go-json-empty-p field))
           nil)
          (t (setf (gethash key result) (go-json-view field type))))))))

(defun daemonset-revision-data (daemonset)
  "Build the patch a ControllerRevision records: DaemonSet Go JSON with spec.template set to replace."
  (let* ((template (go-json-view (copy-core-object (gethash "template" (gethash "spec" daemonset)))
                                 "k8s.io.api.core.v1.PodTemplateSpec"))
         (replace (core-object "$patch" "replace")))
    (unless (gethash "metadata" template) (setf (gethash "metadata" replace) (core-object)))
    (dolist (key (sort (loop for key being the hash-keys of template collect key) #'string<))
      (setf (gethash key replace) (gethash key template)))
    (core-object "spec" (core-object "template" replace))))

(defun revision-template-key (data)
  "Return the Pod template revision DATA records, defaulted and in its Go JSON view."
  (let ((template (defaulted-pod-template (gethash "template" (gethash "spec" data) (core-object)))))
    (remhash "$patch" template)
    (go-json-view template "k8s.io.api.core.v1.PodTemplateSpec")))

(defun revision-data-equal-p (left right)
  "Return whether revision data LEFT and RIGHT record the same template, whichever of them was
stored by an older gr8s without the API defaults: a template that gains its defaults on its
next write is not a new revision, and must not roll every Pod."
  (or (workload-equal-p left right)
      (workload-equal-p (revision-template-key left) (revision-template-key right))))

(defun daemonset-revision-hash (data collision)
  "Hash revision DATA and the collision count into a label value and name suffix."
  (string-downcase
   (subseq (octets-to-hex
            (ironclad:digest-sequence
             :sha256 (trivial-utf-8:string-to-utf-8-bytes
                      (concatenate 'string (canonical-workload-json data) (write-to-string collision)))))
           0 10)))

(defun daemonset-revision-label (revision)
  "Return REVISION's hash label, which a client-created revision may lack."
  (let ((labels (gethash "labels" (workload-metadata revision))))
    (or (and labels (gethash +controller-revision-hash-label+ labels))
        (gethash "name" (workload-metadata revision)))))

(defun add-revision-owner (store daemonset revision)
  "Adopt an unowned REVISION whose labels match DAEMONSET."
  (update-core-resource store "controllerrevisions" (gethash "namespace" (workload-metadata revision))
                        (gethash "name" (workload-metadata revision))
    (lambda (current)
      (unless (equal (gethash "uid" (workload-metadata current)) (gethash "uid" (workload-metadata revision)))
        (core-resource-error 409 "Conflict" "Revision identity has changed"))
      (setf (gethash "ownerReferences" (workload-metadata current))
            (concatenate 'vector (gethash "ownerReferences" (workload-metadata current) #())
                         (vector (workload-owner-reference daemonset))))
      current)))

(defun daemonset-revisions (store daemonset)
  "Claim DAEMONSET's ControllerRevisions, adopting matching orphans and releasing mismatches."
  (let ((selector (workload-spec-selector daemonset)) (result nil))
    (dolist (revision (list-core-resources store "controllerrevisions" (gethash "namespace" (workload-metadata daemonset))))
      (let* ((metadata (workload-metadata revision))
             (matches (workload-selector-matches-p selector (gethash "labels" metadata)))
             (owned (workload-owned-p revision daemonset)))
        (cond ((and owned matches) (push revision result))
              (owned (detach-workload-dependent store "controllerrevisions" daemonset revision))
              ((and matches (null (workload-controller-reference revision)))
               (push (add-revision-owner store daemonset revision) result)))))
    (sort result #'< :key (lambda (revision) (gethash "revision" revision)))))

(defun bump-daemonset-collision-count (store owner count)
  "Durably record a revision name collision of OWNER so the next pass hashes differently."
  (let ((resource (workload-owner-resource owner)))
    (with-store-lock (store)
      (let ((current (workload-current-unlocked store resource owner)))
        (when current
          (let ((copy (copy-core-object current)) (resources (copy-core-resource-index store))
                (revision (1+ (pod-store-resource-revision store))))
            (setf (gethash "collisionCount" (gethash "status" copy)) count)
            (prepare-core-resource-metadata copy current revision)
            (setf (gethash (core-resource-key resource (gethash "namespace" (workload-metadata copy))
                                              (gethash "name" (workload-metadata copy))) resources) copy)
            (commit-core-resources store resources revision)))))))

(defun create-daemonset-revision (store daemonset data number)
  "Create the ControllerRevision for DAEMONSET's template, or count a name collision and retry later."
  (let* ((metadata (workload-metadata daemonset)) (namespace (gethash "namespace" metadata))
         (collision (gethash "collisionCount" (gethash "status" daemonset) 0))
         (hash (daemonset-revision-hash data collision))
         (name (format nil "~A-~A" (subseq (gethash "name" metadata) 0 (min 242 (length (gethash "name" metadata)))) hash))
         (labels (copy-core-object (gethash "labels" (gethash "metadata" (gethash "template" (gethash "spec" daemonset)))))))
    (setf (gethash +controller-revision-hash-label+ labels) hash)
    (let ((object (core-object "apiVersion" "apps/v1" "kind" "ControllerRevision" "data" data "revision" number
                               "metadata" (core-object "name" name "namespace" namespace "labels" labels
                                                       "ownerReferences" (vector (workload-owner-reference daemonset))))))
      (when (gethash "annotations" metadata)
        (setf (gethash "annotations" (workload-metadata object)) (copy-core-object (gethash "annotations" metadata))))
      (handler-case (with-controller-admission ("daemon-set-controller")
                      (admitted-create-core-resource store "controllerrevisions" object namespace))
        (kubernetes-error (condition)
          (unless (= 409 (kubernetes-error-status-code condition)) (error condition))
          (let ((existing (get-core-resource store "controllerrevisions" namespace name)))
            (if (and (workload-owned-p existing daemonset) (revision-data-equal-p (gethash "data" existing) data))
                existing
                (progn (bump-daemonset-collision-count store daemonset (1+ collision))
                       (core-resource-error 409 "Conflict" "ControllerRevision name collision; the next pass uses a new count")))))))))

(defun daemonset-construct-history (store daemonset)
  "Return the current revision, the other revisions and every hash label meaning the current template.

Kubernetes removes duplicates of the current revision when something next syncs
the DaemonSet, which nothing does for a revision a client just created. This
level-triggered loop syncs always, so it keeps duplicates and ages them out with
the rest of the history instead of deleting one a client is about to use."
  (let* ((revisions (daemonset-revisions store daemonset)) (data (daemonset-revision-data daemonset))
         (matching (remove-if-not (lambda (revision) (revision-data-equal-p (gethash "data" revision) data)) revisions))
         (different (remove-if (lambda (revision) (member revision matching :test #'eq)) revisions))
         (number (1+ (reduce #'max different :key (lambda (revision) (gethash "revision" revision)) :initial-value 0)))
         (current (or (car (last matching)) (create-daemonset-revision store daemonset data number))))
    (when (< (gethash "revision" current) number)
      (setf current (update-owned-workload store "controllerrevisions" current
                      (lambda (object) (setf (gethash "revision" object) number) object))))
    (values current
            (remove-if (lambda (revision) (equal (gethash "uid" (workload-metadata revision))
                                                 (gethash "uid" (workload-metadata current))))
                       revisions)
            (remove-duplicates (cons (daemonset-revision-label current) (mapcar #'daemonset-revision-label matching))
                               :test #'equal))))

(defun daemonset-node-eligible-p (daemonset node)
  "Return whether DAEMONSET's template selects NODE, whose taints it must tolerate.
A daemon Pod ignores a node being cordoned, but needs an agent to run on, and a browser
node only takes one that brings no Secrets, host paths or privileges: a node-exporter
tolerating every taint would otherwise be made for each browser and refused each time."
  (let* ((pod-spec (gethash "spec" (gethash "template" (gethash "spec" daemonset))))
         (template-pod (make-pod :object (core-object "spec" pod-spec))))
    (and (not (node-record-api-only node))
         (spec-tolerates-node-scheduling-p pod-spec node)
         (or (not (gr8s.resources::browser-node-p node))
             (gr8s.resources::spec-suits-browser-node-p pod-spec))
         (node-selector-matches-p (gethash "nodeSelector" pod-spec) node)
         (pod-node-affinity-matches-p template-pod node)
         (member (gethash "nodeName" pod-spec) (list nil "" 'null (node-record-name node)) :test #'equal))))

(defun daemonset-pod-terminal-p (status)
  "Return whether a daemon Pod's observed STATUS has reached a terminal phase."
  (member (gethash "phase" status) '("Failed" "Succeeded") :test #'equal))

(defun daemonset-observations (reconciler daemonset &key claim)
  "Return (pod . status) for DAEMONSET's Pods, oldest first, without those already gone from the node."
  (stable-sort
   (loop for pod in (replica-set-pods reconciler daemonset :claim claim)
         for status = (workload-pod-status reconciler pod)
         unless (and (deletion-requested-p pod) (daemonset-pod-terminal-p status))
           collect (cons pod status))
   #'string<
   :key (lambda (pair) (gethash "creationTimestamp" (workload-metadata (pod-to-object (car pair))) ""))))

(defun daemonset-pods-on-node (observations node-name)
  "Select the observations assigned to NODE-NAME."
  (remove node-name observations :test-not #'equal :key (lambda (pair) (pod-node-name (car pair)))))

(defun delete-daemon-pod (reconciler pod &optional daemonset)
  "Start deleting one exact daemon Pod, tolerating one that is already gone."
  (handler-case (when (and (delete-controller-pod reconciler (pod-namespace pod) (pod-name pod) "daemon-set-controller" :uid (pod-uid pod))
                           daemonset)
                  (record-pod-deleted-event (reconciler-store reconciler) daemonset pod))
    (kubernetes-error (condition)
      (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition)))))

(defun daemon-surge-count (daemonset desired)
  "Return how many extra Pods DAEMONSET's rolling update may run across DESIRED nodes."
  (let* ((strategy (gethash "updateStrategy" (gethash "spec" daemonset)))
         (rolling (and (equal "RollingUpdate" (gethash "type" strategy)) (gethash "rollingUpdate" strategy))))
    (if rolling
        (workload-rollout-count (gethash "maxSurge" rolling 0) desired :round-up t)
        0)))

(defun daemon-excess-pods (daemonset running hashes)
  "Return the Pods to remove from a node whose live Pods are RUNNING, oldest first.
Without surge a node keeps its oldest Pod. A surging node also keeps one old and one new Pod
while the new one is coming up, and gives up the old one once it is unready or replaced."
  (if (zerop (daemon-surge-count daemonset 1))
      (mapcar #'car (cdr running))
      (let* ((minimum (gethash "minReadySeconds" (gethash "spec" daemonset)))
             (new (find-if (lambda (pair) (daemon-pod-updated-p (car pair) hashes)) running))
             (old (find-if-not (lambda (pair) (daemon-pod-updated-p (car pair) hashes)) running))
             (excess (mapcar #'car (remove-if (lambda (pair) (or (eq pair new) (eq pair old))) running))))
        (if (and new old
                 (or (not (pod-status-ready-p (cdr old)))
                     (workload-pod-available-p (cdr new) minimum)))
            (cons (car old) excess)
            excess))))

(defun manage-daemon-pods (reconciler daemonset current observations eligible hashes)
  "Keep the Pods each eligible node should run, replacing terminal ones and removing every other Pod."
  (let ((store (reconciler-store reconciler)) (eligible-names (mapcar #'node-record-name eligible)))
    (dolist (pair observations)
      (let ((name (pod-node-name (car pair))))
        (when (and name (not (member name eligible-names :test #'equal)) (not (deletion-requested-p (car pair))))
          (delete-daemon-pod reconciler (car pair) daemonset))))
    (dolist (name eligible-names)
      (let* ((pods (daemonset-pods-on-node observations name))
             (running (remove-if (lambda (pair) (or (deletion-requested-p (car pair)) (daemonset-pod-terminal-p (cdr pair)))) pods)))
        (dolist (pair pods)
          (when (and (daemonset-pod-terminal-p (cdr pair)) (not (deletion-requested-p (car pair))))
            (delete-daemon-pod reconciler (car pair) daemonset)))
        (dolist (pod (daemon-excess-pods daemonset running hashes))
          (delete-daemon-pod reconciler pod daemonset))
        (when (null pods)
          (create-replica-set-pod store daemonset :node-name name
                                  :labels (list (cons +controller-revision-hash-label+
                                                      (daemonset-revision-label current)))))))))

(defun daemon-pod-updated-p (pod hashes)
  "Return whether POD runs one of the hash labels meaning the current template."
  (let ((labels (gethash "labels" (workload-metadata (pod-to-object pod)))))
    (and labels (member (gethash +controller-revision-hash-label+ labels) hashes :test #'equal))))

(defun surge-daemon-pods (reconciler daemonset current observations eligible hashes)
  "Roll by creating replacements first: every node with an unavailable old Pod, and maxSurge others.
A new Pod's arrival is what frees its node's old Pod, which DAEMON-EXCESS-PODS then removes."
  (let* ((store (reconciler-store reconciler)) (minimum (gethash "minReadySeconds" (gethash "spec" daemonset)))
         (surging 0) (allowed nil) (candidates nil))
    (dolist (node eligible)
      (let* ((name (node-record-name node))
             (running (remove-if (lambda (pair) (or (deletion-requested-p (car pair)) (daemonset-pod-terminal-p (cdr pair))))
                                 (daemonset-pods-on-node observations name)))
             (new (find-if (lambda (pair) (daemon-pod-updated-p (car pair) hashes)) running))
             (old (find-if-not (lambda (pair) (daemon-pod-updated-p (car pair) hashes)) running)))
        (cond ((null old))
              ((and new (not (workload-pod-available-p (cdr new) minimum))) (incf surging))
              (new)
              ((workload-pod-available-p (cdr old) minimum) (push name candidates))
              (t (push name allowed)))))
    (dolist (name (append (nreverse allowed)
                          (let ((candidates (nreverse candidates))
                                (room (max 0 (- (daemon-surge-count daemonset (length eligible)) surging))))
                            (subseq candidates 0 (min room (length candidates))))))
      (create-replica-set-pod store daemonset :node-name name
                              :labels (list (cons +controller-revision-hash-label+
                                                  (daemonset-revision-label current)))))))

(defun roll-daemon-pods (reconciler daemonset observations eligible hashes)
  "Delete out-of-date Pods: unavailable ones at once, available ones within maxUnavailable."
  (let* ((spec (gethash "spec" daemonset)) (minimum (gethash "minReadySeconds" spec))
         (budget (max 1 (workload-rollout-count
                         (gethash "maxUnavailable" (gethash "rollingUpdate" (gethash "updateStrategy" spec)))
                         (length eligible) :round-up t)))
         (candidates nil))
    (dolist (node eligible)
      (let* ((name (node-record-name node))
             (running (remove-if (lambda (pair) (or (deletion-requested-p (car pair)) (daemonset-pod-terminal-p (cdr pair))))
                                 (daemonset-pods-on-node observations name)))
             (pair (first running)))
        (cond ((null pair) (decf budget))
              ((daemon-pod-updated-p (car pair) hashes)
               (unless (workload-pod-available-p (cdr pair) minimum) (decf budget)))
              ((workload-pod-available-p (cdr pair) minimum) (push (car pair) candidates))
              (t (decf budget) (delete-daemon-pod reconciler (car pair) daemonset)))))
    (loop for pod in (nreverse candidates)
          while (plusp budget)
          do (delete-daemon-pod reconciler pod daemonset) (decf budget))))

(defun clean-daemonset-history (store daemonset old observations)
  "Delete the oldest revisions beyond revisionHistoryLimit, keeping any a live Pod still names."
  (let ((excess (- (length old) (gethash "revisionHistoryLimit" (gethash "spec" daemonset))))
        (live (remove-duplicates
               (loop for (pod) in observations
                     for labels = (gethash "labels" (workload-metadata (pod-to-object pod)))
                     when labels collect (gethash +controller-revision-hash-label+ labels))
               :test #'equal)))
    (dolist (revision old)
      (when (and (plusp excess) (not (member (daemonset-revision-label revision) live :test #'equal)))
        (let ((metadata (workload-metadata revision)))
          (when (controller-delete-allowed-p store "controllerrevisions" (gethash "namespace" metadata)
                                             (gethash "name" metadata) "daemon-set-controller")
            (delete-core-resource store "controllerrevisions" (gethash "namespace" metadata)
                                  (gethash "name" metadata) :uid (gethash "uid" metadata))))
        (decf excess)))))

(defun publish-daemonset-status (reconciler daemonset nodes eligible hashes)
  "Report what the nodes and their oldest daemon Pods actually show, keeping client conditions."
  (let* ((store (reconciler-store reconciler)) (minimum (gethash "minReadySeconds" (gethash "spec" daemonset)))
         (observations (remove-if (lambda (pair) (deletion-requested-p (car pair)))
                                  (daemonset-observations reconciler daemonset)))
         (scheduled 0) (ready 0) (available 0) (updated 0) (misscheduled 0))
    (dolist (node nodes)
      (let* ((name (node-record-name node)) (pair (first (daemonset-pods-on-node observations name))))
        (cond ((not (member node eligible :test #'eq)) (when pair (incf misscheduled)))
              (pair
               (incf scheduled)
               (when (pod-status-ready-p (cdr pair)) (incf ready))
               (when (workload-pod-available-p (cdr pair) minimum) (incf available))
               (when (daemon-pod-updated-p (car pair) hashes) (incf updated))))))
    (let* ((live (get-core-resource store "daemonsets" (gethash "namespace" (workload-metadata daemonset))
                                    (gethash "name" (workload-metadata daemonset))))
           (status (copy-core-object (gethash "status" live (core-object))))
           (desired (length eligible)) (unavailable (- desired available)))
      (setf (gethash "observedGeneration" status) (gethash "generation" (workload-metadata daemonset))
            (gethash "desiredNumberScheduled" status) desired
            (gethash "currentNumberScheduled" status) scheduled
            (gethash "numberMisscheduled" status) misscheduled
            (gethash "numberReady" status) ready
            (gethash "numberAvailable" status) available
            (gethash "numberUnavailable" status) unavailable
            (gethash "updatedNumberScheduled" status) updated)
      (update-workload-controller-status store "daemonsets" daemonset status))))

(defun reconcile-daemonset (reconciler daemonset)
  "Converge DAEMONSET: record its revision, place Pods on nodes, roll them and report status."
  (let* ((store (reconciler-store reconciler)) (nodes (list-nodes store))
         (eligible (remove-if-not (lambda (node) (daemonset-node-eligible-p daemonset node)) nodes))
         (rolling (equal "RollingUpdate" (gethash "type" (gethash "updateStrategy" (gethash "spec" daemonset))))))
    (multiple-value-bind (current old hashes) (daemonset-construct-history store daemonset)
      (let ((observations (daemonset-observations reconciler daemonset :claim t)))
        (manage-daemon-pods reconciler daemonset current observations eligible hashes)
        (when rolling
          (if (plusp (daemon-surge-count daemonset (length eligible)))
              (surge-daemon-pods reconciler daemonset current observations eligible hashes)
              (roll-daemon-pods reconciler daemonset observations eligible hashes)))
        (clean-daemonset-history store daemonset old observations))
      (publish-daemonset-status reconciler daemonset nodes eligible hashes))))
