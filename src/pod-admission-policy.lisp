;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: MIT
;;;;
;;;; Purpose:
;;;; Apply RuntimeClass, PriorityClass and LimitRange admission to new Pods, and
;;;; LimitRange enforcement to new PersistentVolumeClaims, in the order upstream
;;;; admission plugins run. Failures are 403 Forbidden, as those plugins report.

(in-package #:gr8s)

(defparameter +runtime-handler-annotation+ "node.gr8s.io/runtime-handler"
  "Carries the admission-resolved RuntimeClass handler to the node creating the sandbox.")

(defun pod-admission-forbidden (control &rest arguments)
  "Reject a Pod the way upstream admission plugins do."
  (apply #'core-resource-error 403 "Forbidden" control arguments))

(defun find-policy-object (store resource name)
  "Return the live cluster-scoped policy object NAME, or NIL when it does not exist."
  (handler-case (get-core-resource store resource nil name)
    (kubernetes-error (condition)
      (unless (= 404 (kubernetes-error-status-code condition)) (error condition)))))

(defun admit-pod-runtime-class (store object)
  "Resolve spec.runtimeClassName into its handler, overhead and scheduling constraints."
  (let* ((spec (gethash "spec" object)) (metadata (gethash "metadata" object))
         (name (gethash "runtimeClassName" spec))
         (annotations (gethash "annotations" metadata)))
    (when annotations (remhash +runtime-handler-annotation+ annotations))
    (if (null name)
        (when (gethash "overhead" spec)
          (pod-admission-forbidden "pod rejected: Pod Overhead set without corresponding RuntimeClass defined Overhead"))
        (let ((class (find-policy-object store "runtimeclasses" name)))
          (unless class (pod-admission-forbidden "pod rejected: RuntimeClass ~S not found" name))
          (let* ((overhead (gethash "overhead" class))
                 (fixed (and overhead (gethash "podFixed" overhead)))
                 (scheduling (gethash "scheduling" class)))
            (when (and (gethash "overhead" spec)
                       (not (and fixed (core-json-equal-p (gethash "overhead" spec) fixed))))
              (pod-admission-forbidden "pod rejected: Pod's Overhead doesn't match RuntimeClass's defined Overhead"))
            (when fixed (setf (gethash "overhead" spec) (copy-core-object fixed)))
            (when scheduling
              (when (gethash "nodeSelector" scheduling)
                (unless (gethash "nodeSelector" spec) (setf (gethash "nodeSelector" spec) (core-object)))
                (maphash (lambda (key value)
                           (multiple-value-bind (old present) (gethash key (gethash "nodeSelector" spec))
                             (when (and present (not (equal old value)))
                               (pod-admission-forbidden
                                "conflict: runtimeClass.scheduling.nodeSelector[~A] = ~A; pod.spec.nodeSelector[~A] = ~A"
                                key value key old)))
                           (setf (gethash key (gethash "nodeSelector" spec)) value))
                         (gethash "nodeSelector" scheduling)))
              (when (gethash "tolerations" scheduling)
                (setf (gethash "tolerations" spec)
                      (concatenate 'vector (gethash "tolerations" spec #())
                                   (remove-if (lambda (toleration)
                                                (find toleration (gethash "tolerations" spec #()) :test #'core-json-equal-p))
                                              (copy-core-object (gethash "tolerations" scheduling))))))))
          (unless annotations
            (setf annotations (core-object) (gethash "annotations" metadata) annotations))
          (setf (gethash +runtime-handler-annotation+ annotations) (gethash "handler" class))))))

(defun default-priority-class (store)
  "Return the live globalDefault PriorityClass, if one exists."
  (find-if (lambda (class) (eq t (gethash "globalDefault" class)))
           (list-core-resources store "priorityclasses")))

(defun admit-pod-priority (store object)
  "Resolve the Pod's priority class into its integer priority and preemption policy."
  (let* ((spec (gethash "spec" object))
         (name (gethash "priorityClassName" spec))
         (class (if name (find-policy-object store "priorityclasses" name) (default-priority-class store))))
    (when (and name (null class))
      (pod-admission-forbidden "no PriorityClass with name ~A was found" name))
    (let ((priority (if class (gethash "value" class) 0))
          (policy (if class (gethash "preemptionPolicy" class "PreemptLowerPriority") "PreemptLowerPriority")))
      (when (and (gethash "priority" spec) (/= priority (gethash "priority" spec)))
        (pod-admission-forbidden
         "the integer value of priority (~D) must not be provided in pod spec; priority admission controller computed ~D from the given PriorityClass name"
         (gethash "priority" spec) priority))
      (when (and (gethash "preemptionPolicy" spec) (not (equal policy (gethash "preemptionPolicy" spec))))
        (pod-admission-forbidden
         "the string value of PreemptionPolicy (~A) must not be provided in pod spec; priority admission controller computed ~A from the given PriorityClass name"
         (gethash "preemptionPolicy" spec) policy))
      (when class (setf (gethash "priorityClassName" spec) (gethash "name" (gethash "metadata" class))))
      (setf (gethash "priority" spec) priority (gethash "preemptionPolicy" spec) policy))))

(defun limit-range-items (store namespace type)
  "Return NAMESPACE's LimitRange items of TYPE, in stored order."
  (loop for range in (list-core-resources store "limitranges" namespace)
        append (coerce (remove type (gethash "limits" (gethash "spec" range) #())
                               :key (lambda (item) (gethash "type" item)) :test-not #'equal)
                       'list)))

(defun apply-limit-range-defaults (spec items)
  "Fill missing container requests and limits from Container LimitRange ITEMS."
  (loop for container across (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec))
        do (dolist (item items)
             (loop for (field target) in '(("default" "limits") ("defaultRequest" "requests"))
                   for defaults = (gethash field item)
                   when (and defaults (plusp (hash-table-count defaults)))
                     do (let ((resources (or (gethash "resources" container)
                                             (setf (gethash "resources" container) (core-object)))))
                          (unless (gethash target resources) (setf (gethash target resources) (core-object)))
                          (maphash (lambda (name value)
                                     (unless (nth-value 1 (gethash name (gethash target resources)))
                                       (setf (gethash name (gethash target resources)) value)))
                                   defaults))))))

(defun limit-minimum-violation (kind name minimum requests limits)
  "Return an upstream-style message when REQUESTS or LIMITS violate MINIMUM of NAME, else NIL."
  (let ((request (gethash name requests)) (limit (gethash name limits))
        (floor-value (policy-value minimum)))
    (cond ((null request)
           (format nil "minimum ~A usage per ~A is ~A.  No request is specified" name kind minimum))
          ((< (policy-value-of request) floor-value)
           (format nil "minimum ~A usage per ~A is ~A, but request is ~A" name kind minimum (policy-value-string (policy-value-of request))))
          ((and limit (< (policy-value-of limit) floor-value))
           (format nil "minimum ~A usage per ~A is ~A, but limit is ~A" name kind minimum (policy-value-string (policy-value-of limit)))))))

(defun limit-maximum-violation (kind name maximum requests limits)
  "Return an upstream-style message when REQUESTS or LIMITS violate MAXIMUM of NAME, else NIL."
  (let ((request (gethash name requests)) (limit (gethash name limits))
        (ceiling-value (policy-value maximum)))
    (cond ((null limit)
           (format nil "maximum ~A usage per ~A is ~A.  No limit is specified" name kind maximum))
          ((> (policy-value-of limit) ceiling-value)
           (format nil "maximum ~A usage per ~A is ~A, but limit is ~A" name kind maximum (policy-value-string (policy-value-of limit))))
          ((and request (> (policy-value-of request) ceiling-value))
           (format nil "maximum ~A usage per ~A is ~A, but request is ~A" name kind maximum (policy-value-string (policy-value-of request)))))))

(defun limit-ratio-violation (kind name ratio requests limits)
  "Return an upstream-style message when the limit to request ratio of NAME exceeds RATIO, else NIL."
  (let ((request (gethash name requests)) (limit (gethash name limits)))
    (cond ((or (null request) (zerop (policy-value-of request)))
           (format nil "~A max limit to request ratio per ~A is ~A, but no request is specified or request is 0" name kind ratio))
          ((null limit)
           (format nil "~A max limit to request ratio per ~A is ~A, but no limit is specified" name kind ratio))
          ((> (/ (policy-value-of limit) (policy-value-of request)) (policy-value ratio))
           (format nil "~A max limit to request ratio per ~A is ~A, but provided ratio is ~A"
                   name kind ratio (policy-value-string (/ (policy-value-of limit) (policy-value-of request))))))))

(defun policy-value-of (amount)
  "Return AMOUNT as a rational, whether stored as a quantity string or already exact."
  (if (stringp amount) (policy-value amount) amount))

(defun limit-item-violations (item kind requests limits)
  "Collect every violation of a LimitRange ITEM by the given REQUESTS and LIMITS."
  (let ((messages nil))
    (flet ((check (field checker)
             (when (gethash field item)
               (maphash (lambda (name value)
                          (let ((message (funcall checker kind name value requests limits)))
                            (when message (push message messages))))
                        (gethash field item)))))
      (check "min" #'limit-minimum-violation)
      (check "max" #'limit-maximum-violation)
      (check "maxLimitRequestRatio" #'limit-ratio-violation))
    (nreverse messages)))

(defun container-resource-map (container kind)
  "Return CONTAINER's KIND (requests or limits) resource list, or an empty one."
  (let ((resources (gethash "resources" container)))
    (or (and resources (gethash kind resources)) (core-object))))

(defun validate-pod-limit-ranges (spec container-items pod-items)
  "Signal Forbidden when SPEC violates a Container or Pod LimitRange."
  (let ((messages nil))
    (dolist (item container-items)
      (loop for container across (concatenate 'vector (gethash "initContainers" spec #()) (gethash "containers" spec))
            do (setf messages
                     (append messages
                             (limit-item-violations item "Container"
                                                    (container-resource-map container "requests")
                                                    (container-resource-map container "limits"))))))
    (when pod-items
      (multiple-value-bind (requests limits) (pod-spec-resource-totals spec :overhead nil)
        (dolist (item pod-items)
          (setf messages (append messages (limit-item-violations item "Pod" requests limits))))))
    (when messages
      (pod-admission-forbidden "~{~A~^; ~}" messages))))

(defun admit-pod-limit-ranges (store namespace object)
  "Apply Container LimitRange defaults to a new Pod, then enforce every LimitRange on it."
  (let ((container-items (limit-range-items store namespace "Container"))
        (pod-items (limit-range-items store namespace "Pod"))
        (spec (gethash "spec" object)))
    (when container-items (apply-limit-range-defaults spec container-items))
    (when (or container-items pod-items)
      (validate-pod-limit-ranges spec container-items pod-items))))

(defun admit-pod-policies (store pod)
  "Run mutating Pod admission and return the revalidated POD."
  (let* ((object (copy-core-object (pod-to-object pod)))
         (namespace (pod-namespace pod)))
    (admit-pod-limit-ranges store namespace object)
    (admit-pod-priority store object)
    (admit-pod-runtime-class store object)
    (parse-pod object :allow-generate-name (null (pod-name pod)))))

(defun enforce-claim-limit-ranges-unlocked (store namespace object)
  "Enforce storage LimitRanges on a new claim while STORE's lock is held."
  (let ((request (let* ((resources (gethash "resources" (gethash "spec" object)))
                        (requests (and resources (gethash "requests" resources))))
                   (and requests (gethash "storage" requests))))
        (messages nil))
    (loop for key being the hash-keys of (pod-store-resources store) using (hash-value range)
          do (when (and (equal "limitranges" (first key)) (equal namespace (second key)))
               (loop for item across (gethash "limits" (gethash "spec" range) #())
                     do (when (equal "PersistentVolumeClaim" (gethash "type" item))
                          (flet ((bound (field) (and (gethash field item) (gethash "storage" (gethash field item)))))
                            (when (and (bound "min") (or (null request) (< (policy-value request) (policy-value (bound "min")))))
                              (push (format nil "minimum storage usage per PersistentVolumeClaim is ~A, but request is ~A"
                                            (bound "min") request)
                                    messages))
                            (when (and (bound "max") (or (null request) (> (policy-value request) (policy-value (bound "max")))))
                              (push (format nil "maximum storage usage per PersistentVolumeClaim is ~A, but request is ~A"
                                            (bound "max") request)
                                    messages)))))))
    (when messages (pod-admission-forbidden "~{~A~^; ~}" (nreverse messages)))))

(defun validate-pod-policy-update (existing replacement)
  "Keep requirements immutable and preserve fields admission resolved at Pod creation."
  (let ((old (gethash "spec" (pod-to-object existing)))
        (new (gethash "spec" (pod-to-object replacement))))
    ;; A client's GET-free PUT may omit fields only admission set.
    (dolist (field '("priority" "preemptionPolicy" "priorityClassName" "overhead" "runtimeClassName"
                     "schedulerName" "readinessGates"))
      (multiple-value-bind (value present) (gethash field old)
        (when (and present (not (nth-value 1 (gethash field new))))
          (setf (gethash field new) (copy-core-object value))))
      (unless (or (core-json-equal-p (gethash field old) (gethash field new))
                  ;; A Pod stored before schedulerName was defaulted already meant the default.
                  (and (equal field "schedulerName") (not (nth-value 1 (gethash field old)))
                       (equal +default-scheduler-name+ (gethash field new))))
        (invalid-pod "spec.~A is immutable" field)))
    (let ((old-annotations (gethash "annotations" (gethash "metadata" (pod-to-object existing))))
          (new-metadata (gethash "metadata" (pod-to-object replacement))))
      (let ((handler (and old-annotations (gethash +runtime-handler-annotation+ old-annotations))))
        (when handler
          (unless (gethash "annotations" new-metadata) (setf (gethash "annotations" new-metadata) (core-object)))
          (setf (gethash +runtime-handler-annotation+ (gethash "annotations" new-metadata)) handler))))
    ;; Scheduling gates can only be removed, as upstream validates.
    (let ((before (map 'list (lambda (gate) (gethash "name" gate)) (gethash "schedulingGates" old #()))))
      (loop for gate across (gethash "schedulingGates" new #())
            unless (member (gethash "name" gate) before :test #'equal)
              do (invalid-pod "spec.schedulingGates: Forbidden: only deletion is allowed, but found new scheduling gate '~A'"
                              (gethash "name" gate))))
    (let ((old-deadline (gethash "activeDeadlineSeconds" old))
          (new-deadline (gethash "activeDeadlineSeconds" new)))
      (when old-deadline
        (unless (and new-deadline (<= new-deadline old-deadline))
          (invalid-pod "spec.activeDeadlineSeconds may only be lowered once set"))))
    (loop for field in '("containers" "initContainers")
          do (loop for before across (gethash field old #())
                   for after = (find (gethash "name" before) (gethash field new #())
                                     :key (lambda (container) (gethash "name" container)) :test #'equal)
                   do (when (and after (not *pod-resize-update*)
                                 (not (core-json-equal-p
                                       (or (gethash "resources" before) (core-object))
                                       (or (gethash "resources" after) (core-object)))))
                        (invalid-pod "spec.~A[~A].resources is immutable" field (gethash "name" before)))))))
