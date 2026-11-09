;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Account ResourceQuota usage from live stored objects and refuse writes that
;;;; would exceed a hard limit. Admission runs under the store lock against the
;;;; objects themselves, so concurrent creates cannot both spend the same quota;
;;;; the reconciled status only reports what admission already enforces.

(in-package #:gr8s.resources)

(defun quota-count-resource (name)
  "Map a count/<plural>[.<group>] quota NAME to its internal collection."
  (let* ((reference (subseq name (length "count/")))
         (dot (position #\. reference))
         (plural (if dot (subseq reference 0 dot) reference))
         (group (if dot (subseq reference (1+ dot)) "")))
    (cond ((and (equal plural "pods") (equal group "")) "pods")
          (t (let ((type (find-if (lambda (type)
                                    (and (equal plural (first type))
                                         (let* ((version (third type)) (slash (position #\/ version)))
                                           (equal group (if slash (subseq version 0 slash) "")))))
                                  *stored-resource-types*)))
               (cond (type (first type))
                     ((plusp (length group)) (format nil "custom:~A/~A" group plural))))))))

(defun quota-key-resource (name)
  "Return the collection whose objects consume hard quota resource NAME, or NIL when untracked."
  (cond ((quota-count-resource-name-p name) (quota-count-resource name))
        ((member name '("pods" "cpu" "memory" "ephemeral-storage" "requests.cpu" "requests.memory"
                        "requests.ephemeral-storage" "limits.cpu" "limits.memory" "limits.ephemeral-storage")
                 :test #'equal)
         "pods")
        ((or (quota-extended-request-name-p name) (quota-hugepage-resource-name name)) "pods")
        ((member name '("services" "services.nodeports" "services.loadbalancers") :test #'equal) "services")
        ((member name '("persistentvolumeclaims" "requests.storage") :test #'equal) "persistentvolumeclaims")
        ((nth-value 1 (quota-storage-class-resource name)) "persistentvolumeclaims")
        ((member name '("secrets" "configmaps" "replicationcontrollers" "resourcequotas") :test #'equal) name)))

(defun quota-pod-usage (name requests limits)
  "Return the amount of hard resource NAME one counted Pod uses."
  (flet ((amount (table resource) (gethash resource table 0)))
    (cond ((member name '("pods" "count/pods") :test #'equal) 1)
          ((member name '("cpu" "requests.cpu") :test #'equal) (amount requests "cpu"))
          ((member name '("memory" "requests.memory") :test #'equal) (amount requests "memory"))
          ((member name '("ephemeral-storage" "requests.ephemeral-storage") :test #'equal)
           (amount requests "ephemeral-storage"))
          ((equal name "limits.cpu") (amount limits "cpu"))
          ((equal name "limits.memory") (amount limits "memory"))
          ((equal name "limits.ephemeral-storage") (amount limits "ephemeral-storage"))
          ((quota-extended-request-name-p name) (amount requests (subseq name (length "requests."))))
          ((quota-hugepage-resource-name name) (amount requests (quota-hugepage-resource-name name)))
          (t 0))))

(defun quota-service-usage (name object)
  "Return the amount of hard resource NAME one Service OBJECT uses."
  (let* ((spec (gethash "spec" object))
         (type (gethash "type" spec "ClusterIP"))
         (ports (length (gethash "ports" spec #()))))
    (cond ((member name '("services" "count/services") :test #'equal) 1)
          ((equal name "services.loadbalancers") (if (equal type "LoadBalancer") 1 0))
          ((equal name "services.nodeports")
           (cond ((equal type "NodePort") ports)
                 ((and (equal type "LoadBalancer")
                       (not (eq nil (gethash "allocateLoadBalancerNodePorts" spec t))))
                  ports)
                 (t 0)))
          (t 0))))

(defun quota-claim-usage (name object)
  "Return the amount of hard resource NAME one PersistentVolumeClaim OBJECT uses."
  (let* ((spec (gethash "spec" object))
         (resources (gethash "resources" spec))
         (requests (and resources (gethash "requests" resources)))
         (storage (let ((text (and requests (gethash "storage" requests)))) (if text (policy-value text) 0)))
         (class (gethash "storageClassName" spec)))
    (multiple-value-bind (scoped-class resource) (quota-storage-class-resource name)
      (cond ((member name '("persistentvolumeclaims" "count/persistentvolumeclaims") :test #'equal) 1)
            ((equal name "requests.storage") storage)
            ((not (equal scoped-class class)) 0)
            ((equal resource "requests.storage") storage)
            ((equal resource "persistentvolumeclaims") 1)
            (t 0)))))

(defun quota-pod-charged-p (store pod)
  "Return whether POD still consumes quota: not terminal and not stuck past its deletion grace."
  (and (not (member (gethash (pod-uid pod) (pod-store-pod-observed-phases store))
                    '("Succeeded" "Failed") :test #'equal))
       (not (and (deletion-requested-p pod)
                 (< (pod-deletion-deadline pod) (funcall *pod-deletion-clock*))))))

(defun quota-pod-best-effort-p (object)
  "Return whether a Pod's QoS class is BestEffort: no CPU or memory requested or limited anywhere."
  (let ((spec (gethash "spec" object)))
    (loop for container across (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec))
          never (loop for kind in '("requests" "limits")
                      thereis (let ((values (container-resource-map container kind)))
                                (or (gethash "cpu" values) (gethash "memory" values)))))))

(defun quota-pod-terminating-p (object)
  "Return whether a Pod declares an active deadline, the Terminating quota scope."
  (let ((deadline (gethash "activeDeadlineSeconds" (gethash "spec" object))))
    (and deadline (>= deadline 0))))

(defun quota-scope-matches-pod-p (scope object)
  "Return whether a Pod OBJECT is within a simple quota SCOPE."
  (cond ((equal scope "Terminating") (quota-pod-terminating-p object))
        ((equal scope "NotTerminating") (not (quota-pod-terminating-p object)))
        ((equal scope "BestEffort") (quota-pod-best-effort-p object))
        ((equal scope "NotBestEffort") (not (quota-pod-best-effort-p object)))
        ((equal scope "PriorityClass") (gethash "priorityClassName" (gethash "spec" object)))
        ((equal scope "CrossNamespacePodAffinity") (pod-cross-namespace-affinity-p object))))

(defun quota-selector-term-matches-pod-p (term object)
  "Evaluate one scopeSelector expression against a Pod OBJECT."
  (let ((scope (gethash "scopeName" term)) (operator (gethash "operator" term)))
    (if (equal scope "PriorityClass")
        (let ((class (gethash "priorityClassName" (gethash "spec" object)))
              (values (gethash "values" term #())))
          (cond ((equal operator "In") (and class (find class values :test #'equal)))
                ((equal operator "NotIn") (not (and class (find class values :test #'equal))))
                ((equal operator "Exists") class)
                (t (not class))))
        (quota-scope-matches-pod-p scope object))))

(defun quota-matches-pod-p (spec object)
  "Return whether every scope of quota SPEC covers a Pod OBJECT."
  (and (every (lambda (scope) (quota-scope-matches-pod-p scope object)) (gethash "scopes" spec #()))
       (let ((selector (gethash "scopeSelector" spec)))
         (or (null selector)
             (every (lambda (term) (quota-selector-term-matches-pod-p term object))
                    (gethash "matchExpressions" selector #()))))))

(defun quota-object-usage (spec name resource object)
  "Return how much of hard resource NAME one OBJECT of RESOURCE consumes under quota SPEC."
  (cond ((equal resource "pods")
         (if (quota-matches-pod-p spec object)
             (multiple-value-bind (requests limits) (pod-spec-resource-totals (gethash "spec" object))
               (quota-pod-usage name requests limits))
             0))
        ((quota-spec-scopes spec) 0)
        ((equal resource "services") (quota-service-usage name object))
        ((equal resource "persistentvolumeclaims") (quota-claim-usage name object))
        (t 1)))

(defun quota-used-amount-unlocked (store namespace spec name)
  "Sum hard resource NAME over NAMESPACE's live objects, or return NIL when NAME is untracked."
  (let ((resource (quota-key-resource name)))
    (when resource
      (if (equal resource "pods")
          (loop for pod being the hash-values of (pod-store-pods store)
                when (and (equal namespace (pod-namespace pod)) (quota-pod-charged-p store pod))
                  sum (quota-object-usage spec name resource (pod-to-object pod)))
          (loop for key being the hash-keys of (pod-store-resources store) using (hash-value object)
                when (and (equal resource (first key)) (equal namespace (second key)))
                  sum (quota-object-usage spec name resource object))))))

(defun quota-desired-status-unlocked (store quota)
  "Compute a quota's status: hard mirrored from spec and usage for every tracked resource."
  (let* ((metadata (gethash "metadata" quota)) (namespace (gethash "namespace" metadata))
         (spec (gethash "spec" quota)) (hard (gethash "hard" spec))
         (used (core-object)))
    (when hard
      (maphash (lambda (name limit)
                 (let ((amount (quota-used-amount-unlocked store namespace spec name)))
                   (when amount
                     (setf (gethash name used)
                           (policy-value-string amount (container-quantity-format (parse-container-quantity limit)))))))
               hard))
    (core-object "hard" (copy-core-object (or hard (core-object))) "used" used)))

(defun reconcile-resource-quotas (store)
  "Publish each ResourceQuota's actual usage, undoing any foreign status edit."
  (dolist (quota (list-core-resources store "resourcequotas"))
    (let* ((metadata (gethash "metadata" quota))
           (desired (with-store-lock (store) (quota-desired-status-unlocked store quota))))
      (unless (core-json-equal-p desired (gethash "status" quota (core-object)))
        (handler-case
            (let ((*policy-status-write* t))
              (update-core-resource store "resourcequotas" (gethash "namespace" metadata) (gethash "name" metadata)
                                    (lambda (current)
                                      (setf (gethash "status" current) desired)
                                      current)))
          (kubernetes-error (condition)
            ;; A concurrent delete or spec change resolves on the next pass.
            (unless (member (kubernetes-error-status-code condition) '(404 409)) (error condition))))))))

(defun quota-pod-missing-requirements (hard object)
  "Name containers that omit a CPU or memory amount the quota HARD set constrains."
  (let ((messages nil) (spec (gethash "spec" object)))
    (loop for (quota-names kind resource) in '((("cpu" "requests.cpu") "requests" "cpu")
                                               (("memory" "requests.memory") "requests" "memory")
                                               (("limits.cpu") "limits" "cpu")
                                               (("limits.memory") "limits" "memory"))
          do (when (some (lambda (name) (nth-value 1 (gethash name hard))) quota-names)
               (let ((missing (loop for container across (concatenate 'vector (gethash "initContainers" spec #())
                                                                      (gethash "containers" spec))
                                    unless (gethash resource (container-resource-map container kind))
                                      collect (gethash "name" container))))
                 (when missing
                   (push (format nil "must specify ~A.~A for: ~{~A~^,~}" kind resource missing) messages)))))
    (nreverse messages)))

(defun enforce-resource-quotas-unlocked (store resource namespace object &optional existing)
  "Refuse OBJECT with 403 when its added usage would exceed a live quota's hard limit."
  (when (or *resource-quota-admission-exempt* (null namespace))
    (return-from enforce-resource-quotas-unlocked nil))
  (loop for key being the hash-keys of (pod-store-resources store) using (hash-value quota)
        do (when (and (equal "resourcequotas" (first key)) (equal namespace (second key)))
             (let* ((spec (gethash "spec" quota)) (hard (gethash "hard" spec)))
               (when hard
                 (when (and (equal resource "pods") (null existing) (quota-matches-pod-p spec object))
                   (let ((missing (quota-pod-missing-requirements hard object)))
                     (when missing
                       (core-resource-error 403 "Forbidden" "failed quota: ~A: ~{~A~^; ~}" (third key) missing))))
                 (maphash
                  (lambda (name limit)
                    (when (equal resource (quota-key-resource name))
                      (let ((delta (- (quota-object-usage spec name resource object)
                                      (if existing (quota-object-usage spec name resource existing) 0))))
                        (when (plusp delta)
                          (let ((used (quota-used-amount-unlocked store namespace spec name))
                                (allowed (policy-value limit)))
                            (when (> (+ used delta) allowed)
                              (core-resource-error
                               403 "Forbidden" "exceeded quota: ~A, requested: ~A=~A, used: ~A=~A, limited: ~A=~A"
                               (third key) name (policy-value-string delta) name (policy-value-string used) name limit)))))))
                  hard)))))
  nil)
