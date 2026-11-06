;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Honour spec.topologySpreadConstraints as the scheduler's PodTopologySpread plugin
;;;; does. Nodes carrying a constraint's topologyKey form its domains, each counting the
;;;; Pods in the incoming Pod's namespace that its labelSelector selects. A
;;;; DoNotSchedule constraint refuses a node whose domain would then exceed the
;;;; smallest by more than maxSkew; a ScheduleAnyway one prefers the least crowded
;;;; domains. A node without every required key is in no domain and is refused.

(in-package #:gr8s)

(defparameter +topology-spread-failure+ "node(s) didn't match pod topology spread constraints"
  "The scheduler's reason for a node a DoNotSchedule constraint refuses.")

(defparameter +topology-spread-constraint-fields+
  '("maxSkew" "topologyKey" "whenUnsatisfiable" "labelSelector" "minDomains"
    "nodeAffinityPolicy" "nodeTaintsPolicy" "matchLabelKeys"))

(defun validate-topology-spread-constraints (spec)
  "Validate spec.topologySpreadConstraints as the API server's ValidateTopologySpreadConstraints does."
  (when (eq (gethash "topologySpreadConstraints" spec) 'null) (remhash "topologySpreadConstraints" spec))
  (let ((seen nil))
    (loop for constraint across (optional-vector spec "topologySpreadConstraints" "spec")
          for index from 0
          for path = (format nil "spec.topologySpreadConstraints[~D]" index)
          do (drop-null-fields (require-object constraint path))
             (reject-unsupported-fields constraint +topology-spread-constraint-fields+ path)
             (let ((skew (gethash "maxSkew" constraint))
                   (key (gethash "topologyKey" constraint))
                   (when (gethash "whenUnsatisfiable" constraint))
                   (domains (gethash "minDomains" constraint))
                   (selector (gethash "labelSelector" constraint))
                   (keys (optional-vector constraint "matchLabelKeys" path)))
               (unless (typep skew '(integer 1 #x7fffffff))
                 (invalid-pod "~A.maxSkew: Invalid value: ~A: must be greater than zero" path skew))
               (unless (and (stringp key) (plusp (length key)))
                 (invalid-pod "~A.topologyKey: Required value: can not be empty" path))
               (unless (core-qualified-key-p key)
                 (invalid-pod "~A.topologyKey: Invalid value: ~S: must be a qualified name" path key))
               (unless (member when '("DoNotSchedule" "ScheduleAnyway") :test #'equal)
                 (invalid-pod "~A.whenUnsatisfiable: Unsupported value: ~S: supported values: \"DoNotSchedule\", \"ScheduleAnyway\""
                              path when))
               (when (member (cons key when) seen :test #'equal)
                 (invalid-pod "~A.{topologyKey, whenUnsatisfiable}: Duplicate value: \"{~A, ~A}\"" path key when))
               (push (cons key when) seen)
               (when domains
                 (unless (typep domains '(integer 1 #x7fffffff))
                   (invalid-pod "~A.minDomains: Invalid value: ~A: must be greater than 0" path domains))
                 (unless (equal when "DoNotSchedule")
                   (invalid-pod "~A.minDomains: Invalid value: ~A: can only use minDomains if whenUnsatisfiable=DoNotSchedule"
                                path domains)))
               (dolist (field '("nodeAffinityPolicy" "nodeTaintsPolicy"))
                 (let ((policy (gethash field constraint)))
                   (when (and policy (not (member policy '("Honor" "Ignore") :test #'equal)))
                     (invalid-pod "~A.~A: Unsupported value: ~S: supported values: \"Honor\", \"Ignore\"" path field policy))))
               (when selector (validate-workload-selector selector :allow-empty t))
               (when (and (plusp (length keys)) (null selector))
                 (invalid-pod "~A.matchLabelKeys: Forbidden: must not be specified when labelSelector is not set" path))
               (loop for label across keys
                     for position from 0
                     do (unless (core-qualified-key-p label)
                          (invalid-pod "~A.matchLabelKeys[~D]: Invalid value: ~S: must be a valid label key"
                                       path position label))
                        (when (and selector (gethash "matchLabels" selector)
                                   (nth-value 1 (gethash label (gethash "matchLabels" selector))))
                          (invalid-pod "~A.matchLabelKeys[~D]: Invalid value: ~S: exists in both matchLabelKeys and labelSelector"
                                       path position label)))))))

(defun merge-topology-spread-match-label-keys (pod)
  "Add each matchLabelKeys label POD carries to its constraint's labelSelector, as Pod creation does.
The API server merges them into matchExpressions as `key In (value)`; a key the Pod lacks is ignored."
  (let* ((object (pod-to-object pod))
         (labels (gethash "labels" (gethash "metadata" object))))
    (loop for constraint across (gethash "topologySpreadConstraints" (gethash "spec" object) #())
          for selector = (gethash "labelSelector" constraint)
          when selector
            do (loop for key across (gethash "matchLabelKeys" constraint #())
                     when (and labels (stringp (gethash key labels)))
                       do (setf (gethash "matchExpressions" selector)
                                (concatenate 'vector (gethash "matchExpressions" selector #())
                                             (vector (core-object "key" key "operator" "In"
                                                                  "values" (vector (gethash key labels))))))))
    pod))

(defun pod-topology-spread-constraints (pod when-unsatisfiable)
  "Return POD's topology spread constraints whose whenUnsatisfiable is WHEN-UNSATISFIABLE."
  (loop for constraint across (gethash "topologySpreadConstraints" (gethash "spec" (pod-to-object pod)) #())
        when (equal when-unsatisfiable (gethash "whenUnsatisfiable" constraint))
          collect constraint))

(defun topology-labels-have-keys-p (labels keys)
  "Return whether node LABELS carry every topology key in KEYS."
  (every (lambda (key) (and labels (nth-value 1 (gethash key labels)))) keys))

(defun topology-constraint-selects-p (constraint labels)
  "Return whether CONSTRAINT's labelSelector selects LABELS; without one it selects nothing."
  (let ((selector (gethash "labelSelector" constraint)))
    (and selector (workload-selector-matches-p selector labels))))

(defun topology-node-included-p (pod constraint node)
  "Apply CONSTRAINT's nodeAffinityPolicy (default Honor) and nodeTaintsPolicy (default Ignore) to NODE."
  (and (or (equal "Ignore" (gethash "nodeAffinityPolicy" constraint))
           (and (pod-node-selector-matches-p pod node) (pod-node-affinity-matches-p pod node)))
       (or (not (equal "Honor" (gethash "nodeTaintsPolicy" constraint)))
           (spec-tolerates-node-scheduling-p (gethash "spec" (pod-to-object pod)) node))))

(defun topology-spread-domain-counts-unlocked (store pod constraint keys)
  "Count, per domain of CONSTRAINT, the Pods it selects in POD's namespace.
Only nodes carrying all KEYS that CONSTRAINT's node policies include form domains; a domain
with no matching Pod counts zero. Terminating and finished Pods don't count."
  (let ((counts (make-hash-table :test #'equal))
        (domains (make-hash-table :test #'equal))
        (key (gethash "topologyKey" constraint)))
    (loop for node being the hash-values of (pod-store-nodes store)
          for labels = (storage-node-labels node)
          when (and (topology-labels-have-keys-p labels keys) (topology-node-included-p pod constraint node))
            do (setf (gethash (node-record-name node) domains) (gethash key labels)
                     (gethash (gethash key labels) counts) (gethash (gethash key labels) counts 0)))
    (loop for other being the hash-values of (pod-store-pods store)
          for domain = (and (pod-node-name other) (gethash (pod-node-name other) domains))
          when (and domain
                    (not (equal (pod-uid other) (pod-uid pod)))
                    (equal (pod-namespace other) (pod-namespace pod))
                    (not (deletion-requested-p other))
                    (not (terminal-pod-phase-p (gethash (pod-uid other) (pod-store-pod-observed-phases store))))
                    (topology-constraint-selects-p constraint (pod-object-labels (pod-to-object other))))
            do (incf (gethash domain counts)))
    counts))

(defun topology-spread-minimum (constraint counts)
  "Return the smallest domain count, 0 when fewer domains exist than minDomains, or NIL with none."
  (let ((wanted (gethash "minDomains" constraint)))
    (cond ((and wanted (< (hash-table-count counts) wanted)) 0)
          ((zerop (hash-table-count counts)) nil)
          (t (loop for count being the hash-values of counts minimize count)))))

(defun pod-topology-spread-failure-unlocked (store pod node)
  "Return why NODE breaks one of POD's DoNotSchedule spread constraints, as the scheduler words it, or NIL."
  (let ((constraints (pod-topology-spread-constraints pod "DoNotSchedule")))
    (when constraints
      (let ((keys (mapcar (lambda (constraint) (gethash "topologyKey" constraint)) constraints))
            (labels (storage-node-labels node))
            (own (pod-object-labels (pod-to-object pod))))
        (if (not (topology-labels-have-keys-p labels keys))
            (concatenate 'string +topology-spread-failure+ " (missing required label)")
            (loop for constraint in constraints
                  for counts = (topology-spread-domain-counts-unlocked store pod constraint keys)
                  for minimum = (topology-spread-minimum constraint counts)
                  for skew = (and minimum
                                  (- (+ (gethash (gethash (gethash "topologyKey" constraint) labels) counts 0)
                                        (if (topology-constraint-selects-p constraint own) 1 0))
                                     minimum))
                  when (and skew (> skew (gethash "maxSkew" constraint)))
                    return +topology-spread-failure+))))))

(defun pod-topology-spread-penalty-unlocked (store pod node)
  "Score how crowded NODE's domains are for POD's ScheduleAnyway constraints; lower is better.
As the plugin's scoring does, each domain's matching Pods count, weighted by the log of how many
domains its constraint has; a node lacking a key ranks last."
  (let ((constraints (pod-topology-spread-constraints pod "ScheduleAnyway")))
    (if (null constraints)
        0
        (let ((keys (mapcar (lambda (constraint) (gethash "topologyKey" constraint)) constraints))
              (labels (storage-node-labels node)))
          (if (not (topology-labels-have-keys-p labels keys))
              most-positive-double-float
              (loop for constraint in constraints
                    for counts = (topology-spread-domain-counts-unlocked store pod constraint keys)
                    sum (* (+ (gethash (gethash (gethash "topologyKey" constraint) labels) counts 0)
                              (1- (gethash "maxSkew" constraint)))
                           (log (+ 2d0 (hash-table-count counts))))))))))
