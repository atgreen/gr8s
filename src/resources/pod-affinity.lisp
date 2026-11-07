;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Evaluate inter-Pod affinity and anti-affinity as the scheduler's InterPodAffinity
;;;; plugin does. A term selects Pods by namespace and labels, and two nodes are in one
;;;; topology domain when they carry the same value for the term's topologyKey. A node
;;;; without the key is in no domain: it fails affinity and cannot violate anti-affinity.

(in-package #:gr8s.resources)

(defun pod-affinity-kind (object kind)
  "Return Pod OBJECT's podAffinity or podAntiAffinity object, named by KIND."
  (let ((affinity (gethash "affinity" (gethash "spec" object))))
    (and affinity (gethash kind affinity))))

(defun pod-required-affinity-terms (pod kind)
  "Return POD's required terms of KIND as a list."
  (let ((group (pod-affinity-kind (pod-to-object pod) kind)))
    (and group (coerce (gethash "requiredDuringSchedulingIgnoredDuringExecution" group #()) 'list))))

(defun pod-preferred-affinity-terms (pod kind)
  "Return POD's preferred terms of KIND as a list of (weight . term)."
  (let ((group (pod-affinity-kind (pod-to-object pod) kind)))
    (and group
         (map 'list (lambda (entry) (cons (gethash "weight" entry) (gethash "podAffinityTerm" entry)))
              (gethash "preferredDuringSchedulingIgnoredDuringExecution" group #())))))

(defun pod-object-labels (object)
  "Return the labels of Pod OBJECT, or NIL."
  (gethash "labels" (gethash "metadata" object)))

(defun affinity-term-namespace-matches-p (store term owner namespace)
  "Return whether TERM of Pod OWNER looks in NAMESPACE; with neither field it means OWNER's own."
  (let ((names (gethash "namespaces" term #())) (selector (gethash "namespaceSelector" term)))
    (cond ((find namespace names :test #'equal) t)
          (selector
           (let ((object (gethash (core-resource-key "namespaces" nil namespace) (pod-store-resources store))))
             (workload-selector-matches-p
              selector (and object (gethash "labels" (gethash "metadata" object))))))
          ((zerop (length names)) (equal namespace (pod-namespace owner))))))

(defun affinity-term-labels-match-p (term owner labels)
  "Apply TERM's selector to LABELS; matchLabelKeys and mismatchLabelKeys compare against Pod OWNER's."
  (let ((selector (gethash "labelSelector" term))
        (own (pod-object-labels (pod-to-object owner))))
    (flet ((owner-value (key) (and own (gethash key own))))
      (and selector
           (workload-selector-matches-p selector labels)
           (loop for key across (gethash "matchLabelKeys" term #())
                 always (or (null (owner-value key))
                            (equal (owner-value key) (and labels (gethash key labels)))))
           (loop for key across (gethash "mismatchLabelKeys" term #())
                 always (or (null (owner-value key))
                            (not (equal (owner-value key) (and labels (gethash key labels))))))))))

(defun affinity-term-selects-pod-p (store term owner target)
  "Return whether TERM of Pod OWNER selects Pod TARGET."
  (and (affinity-term-namespace-matches-p store term owner (pod-namespace target))
       (affinity-term-labels-match-p term owner (pod-object-labels (pod-to-object target)))))

(defun same-topology-domain-p (term left-labels right-labels)
  "Return whether nodes with these labels share TERM's topology domain."
  (let* ((key (gethash "topologyKey" term))
         (left (and left-labels (gethash key left-labels))))
    (and left (equal left (and right-labels (gethash key right-labels))))))

(defun scheduled-pods-with-node-labels-unlocked (store pod)
  "Return (pod . labels) for every other Pod occupying a node, with that node's labels."
  (let ((labels (make-hash-table :test #'equal)))
    (loop for other being the hash-values of (pod-store-pods store)
          for name = (pod-node-name other)
          when (and name (not (equal (pod-uid other) (pod-uid pod)))
                    (not (terminal-pod-phase-p (gethash (pod-uid other) (pod-store-pod-observed-phases store)))))
            collect (cons other
                          (multiple-value-bind (value known) (gethash name labels)
                            (if known
                                value
                                (let ((node (gethash name (pod-store-nodes store))))
                                  (setf (gethash name labels) (and node (storage-node-labels node))))))))))

(defun pod-affinity-failure-unlocked (store pod node)
  "Return why NODE breaks an inter-Pod rule for POD, as the scheduler words it, or NIL."
  (let ((affinity (pod-required-affinity-terms pod "podAffinity"))
        (anti (pod-required-affinity-terms pod "podAntiAffinity")))
    ;; Most Pods have no terms and most clusters have no anti-affinity, so look before building anything.
    (unless (or affinity anti
                (loop for other being the hash-values of (pod-store-pods store)
                        thereis (and (pod-node-name other) (pod-required-affinity-terms other "podAntiAffinity"))))
      (return-from pod-affinity-failure-unlocked nil))
    (let ((existing (scheduled-pods-with-node-labels-unlocked store pod))
          (labels (storage-node-labels node)))
      (or (when (loop for (other . other-labels) in existing
                        thereis (loop for term in (pod-required-affinity-terms other "podAntiAffinity")
                                        thereis (and (same-topology-domain-p term labels other-labels)
                                                     (affinity-term-selects-pod-p store term other pod))))
            "node(s) didn't satisfy existing pods anti-affinity rules")
          (when (loop for term in anti
                        thereis (loop for (other . other-labels) in existing
                                        thereis (and (same-topology-domain-p term labels other-labels)
                                                     (affinity-term-selects-pod-p store term pod other))))
            "node(s) didn't match pod anti-affinity rules")
          (when (and affinity (not (pod-required-affinity-satisfied-p store pod affinity labels existing)))
            "node(s) didn't match pod affinity rules")))))

(defun pod-required-affinity-satisfied-p (store pod terms labels existing)
  "Return whether a node with LABELS meets POD's affinity TERMS; a Pod may start its own group."
  (flet ((selects-all (other)
           (every (lambda (term) (affinity-term-selects-pod-p store term pod other)) terms)))
    (and (every (lambda (term) (and labels (nth-value 1 (gethash (gethash "topologyKey" term) labels)))) terms)
         (let ((matching (remove-if-not (lambda (entry) (selects-all (car entry))) existing)))
           (or (every (lambda (term)
                        (some (lambda (entry) (same-topology-domain-p term labels (cdr entry))) matching))
                      terms)
               ;; Only Pods on nodes that have the key form a domain to join.
               (and (notany (lambda (entry)
                              (some (lambda (term)
                                      (and (cdr entry) (nth-value 1 (gethash (gethash "topologyKey" term) (cdr entry)))))
                                    terms))
                            matching)
                    (selects-all pod)))))))

(defun pod-affinity-preference-score-unlocked (store pod node)
  "Score NODE for POD by the preferred terms on both sides, as the scheduler's scoring does."
  (let ((preferred-affinity (pod-preferred-affinity-terms pod "podAffinity"))
        (preferred-anti (pod-preferred-affinity-terms pod "podAntiAffinity"))
        (labels (storage-node-labels node))
        (score 0))
    (loop for other being the hash-values of (pod-store-pods store)
          when (and (pod-node-name other) (not (equal (pod-uid other) (pod-uid pod))))
            do (let ((other-affinity (pod-preferred-affinity-terms other "podAffinity"))
                     (other-anti (pod-preferred-affinity-terms other "podAntiAffinity"))
                     (other-required (pod-required-affinity-terms other "podAffinity")))
                 (when (or preferred-affinity preferred-anti other-affinity other-anti other-required)
                   (let* ((other-node (gethash (pod-node-name other) (pod-store-nodes store)))
                          (other-labels (and other-node (storage-node-labels other-node))))
                     (flet ((add (entries owner target sign)
                              (loop for (weight . term) in entries
                                    when (and (same-topology-domain-p term labels other-labels)
                                              (affinity-term-selects-pod-p store term owner target))
                                      do (incf score (* sign weight)))))
                       (add preferred-affinity pod other 1)
                       (add preferred-anti pod other -1)
                       (add other-affinity other pod 1)
                       (add other-anti other pod -1)
                       ;; Honouring another Pod's hard affinity counts for a little, as the default weight of 1 does.
                       (add (mapcar (lambda (term) (cons 1 term)) other-required) other pod 1))))))
    score))

(defun pod-cross-namespace-affinity-p (object)
  "Return whether Pod OBJECT has an affinity term reaching beyond its own namespace."
  (flet ((crossing (term) (or (plusp (length (gethash "namespaces" term #())))
                              (gethash "namespaceSelector" term))))
    (loop for kind in '("podAffinity" "podAntiAffinity")
          for group = (pod-affinity-kind object kind)
            thereis (and group
                         (or (some #'crossing (gethash "requiredDuringSchedulingIgnoredDuringExecution" group #()))
                             (some (lambda (entry) (crossing (gethash "podAffinityTerm" entry)))
                                   (gethash "preferredDuringSchedulingIgnoredDuringExecution" group #())))))))

(defun validate-pod-affinity-term (term)
  "Validate one PodAffinityTerm."
  (drop-null-fields (require-object term "pod affinity term"))
  (reject-unsupported-fields term '("labelSelector" "namespaces" "namespaceSelector" "topologyKey"
                                    "matchLabelKeys" "mismatchLabelKeys")
                             "pod affinity term")
  (unless (core-qualified-key-p (gethash "topologyKey" term))
    (invalid-pod "pod affinity term requires a valid topologyKey"))
  (dolist (field '("labelSelector" "namespaceSelector"))
    (when (gethash field term)
      (validate-workload-selector (gethash field term) :allow-empty t)))
  (loop for namespace across (optional-vector term "namespaces" "pod affinity term")
        do (unless (dns-label-p namespace)
             (invalid-pod "pod affinity term namespace ~S is invalid" namespace)))
  (let ((match (optional-vector term "matchLabelKeys" "pod affinity term"))
        (mismatch (optional-vector term "mismatchLabelKeys" "pod affinity term")))
    (when (and (or (plusp (length match)) (plusp (length mismatch))) (null (gethash "labelSelector" term)))
      (invalid-pod "matchLabelKeys and mismatchLabelKeys require a labelSelector"))
    (loop for key across (concatenate 'vector match mismatch)
          do (unless (core-qualified-key-p key)
               (invalid-pod "pod affinity label key ~S is invalid" key)))
    (when (some (lambda (key) (find key mismatch :test #'equal)) match)
      (invalid-pod "matchLabelKeys and mismatchLabelKeys must not share a key"))))

(defun validate-pod-affinity-group (group context)
  "Validate one podAffinity or podAntiAffinity object."
  (drop-null-fields (require-object group context))
  (reject-unsupported-fields group '("requiredDuringSchedulingIgnoredDuringExecution"
                                     "preferredDuringSchedulingIgnoredDuringExecution")
                             context)
  (map nil #'validate-pod-affinity-term
       (optional-vector group "requiredDuringSchedulingIgnoredDuringExecution" context))
  (loop for entry across (optional-vector group "preferredDuringSchedulingIgnoredDuringExecution" context)
        do (drop-null-fields (require-object entry "preferred pod affinity"))
           (reject-unsupported-fields entry '("weight" "podAffinityTerm") "preferred pod affinity")
           (unless (typep (gethash "weight" entry) '(integer 1 100))
             (invalid-pod "preferred pod affinity weight must be between 1 and 100"))
           (validate-pod-affinity-term (gethash "podAffinityTerm" entry))))
