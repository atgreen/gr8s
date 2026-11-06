;;;; SPDX-FileCopyrightText: 2026 Anthony Green
;;;; SPDX-License-Identifier: Apache-2.0
;;;;
;;;; Purpose:
;;;; Pod-level spec.resources (PodLevelResources, beta and on by default since
;;;; v1.34). CPU and memory requests and limits for the Pod as a whole replace the
;;;; sum of its containers' in scheduling, quota and QoS, and give a container that
;;;; declares no limit of its own the Pod's, as the downward API reports it.

(in-package #:gr8s)

(defparameter +pod-level-resource-names+ '("cpu" "memory")
  "The resources a Pod may declare for itself; hugepages are not implemented here.")

(defun pod-level-resource-list (spec kind)
  "Return SPEC's pod-level KIND (\"requests\" or \"limits\") table of supported resources, or NIL."
  (let* ((resources (gethash "resources" spec))
         (values (and (hash-table-p resources) (gethash kind resources))))
    (when (and (hash-table-p values)
               (loop for name in +pod-level-resource-names+ thereis (nth-value 1 (gethash name values))))
      values)))

(defun pod-level-resources-set-p (spec)
  "Return whether SPEC declares any supported pod-level request or limit, as IsPodLevelResourcesSet does."
  (or (pod-level-resource-list spec "requests") (pod-level-resource-list spec "limits")))

(defun pod-level-quantity-value (text)
  "Return the exact rational value of quantity TEXT, as POD-SPEC-RESOURCE-TOTALS sums them."
  (let ((quantity (parse-container-quantity text)))
    (* (container-quantity-coefficient quantity) (expt 10 (container-quantity-scale quantity)))))

(defun validate-pod-level-resources (spec)
  "Validate and default spec.resources as the API server does once containers are normalized.
Only cpu and memory are accepted; requests default from the containers' and then from limits; a
request may not exceed its limit, nor fall below what the containers request, and no container may
have a limit above the Pod's."
  (when (eq (gethash "resources" spec) 'null) (remhash "resources" spec))
  (let ((resources (gethash "resources" spec)))
    (unless resources (return-from validate-pod-level-resources nil))
    (drop-null-fields (require-object resources "spec.resources"))
    (reject-unsupported-fields resources '("limits" "requests" "claims") "spec.resources")
    (when (equal "windows" (gethash "name" (gethash "os" spec (core-object))))
      (invalid-pod "spec.resources: Forbidden: may not be set for a windows pod"))
    (when (plusp (length (gethash "claims" resources #())))
      (invalid-pod "spec.resources.claims: Forbidden: claims may not be set for Resources at pod-level"))
    (remhash "claims" resources)
    (dolist (kind '("limits" "requests"))
      (let ((values (gethash kind resources)))
        (when values
          (require-object values (format nil "spec.resources.~A" kind))
          (maphash (lambda (name value)
                     (cond ((member name +pod-level-resource-names+ :test #'equal))
                           ((uiop:string-prefix-p "hugepages-" name)
                            (invalid-pod "spec.resources.~A[~A]: Resource ~S has no implemented enforcement" kind name name))
                           (t (invalid-pod "spec.resources.~A[~A]: Unsupported value: ~S: supported values: \"cpu\", \"hugepages-\", \"memory\""
                                           kind name name)))
                     (let ((quantity (container-quantity-round (parse-container-quantity value) -3)))
                       (when (minusp (container-quantity-coefficient quantity))
                         (invalid-pod "spec.resources.~A[~A]: Invalid value: ~S: must be greater than or equal to 0" kind name value))
                       (setf (gethash name values) (container-quantity-string quantity))))
                   values))))
    (let ((limits (gethash "limits" resources))
          (aggregate (pod-spec-resource-totals spec :overhead nil :pod-level nil)))
      ;; defaultPodRequests: only a Pod that sets limits has its requests filled in.
      (when (and limits (plusp (hash-table-count limits)))
        (let ((requests (or (gethash "requests" resources) (make-hash-table :test #'equal))))
          (dolist (name +pod-level-resource-names+)
            (unless (nth-value 1 (gethash name requests))
              (multiple-value-bind (total present) (gethash name aggregate)
                (cond (present
                       (setf (gethash name requests)
                             (container-quantity-string
                              (container-quantity-round
                               (parse-container-quantity (if (equal name "cpu")
                                                             (format nil "~Dm" (ceiling (* total 1000)))
                                                             (format nil "~D" (ceiling total))))
                               -3))))
                      ((nth-value 1 (gethash name limits))
                       (setf (gethash name requests) (gethash name limits)))))))
          (when (plusp (hash-table-count requests)) (setf (gethash "requests" resources) requests))))
      (let ((requests (gethash "requests" resources)))
        (when requests
          (maphash (lambda (name value)
                     (let ((limit (and limits (gethash name limits))))
                       (when (and limit (plusp (container-quantity-compare (parse-container-quantity value)
                                                                           (parse-container-quantity limit))))
                         (invalid-pod "spec.resources.requests[~A]: Invalid value: ~S: must be less than or equal to ~A limit of ~A"
                                      name value name limit)))
                     (multiple-value-bind (total present) (gethash name aggregate)
                       (when (and present (> total (pod-level-quantity-value value)))
                         (invalid-pod "spec.resources.requests[~A]: Invalid value: ~S: must be greater than or equal to aggregate container requests"
                                      name value))))
                   requests)))
      (when limits
        (loop for container across (gethash "containers" spec #())
              for index from 0
              do (maphash (lambda (name value)
                            (let ((pod-limit (gethash name limits)))
                              (when (and pod-limit (plusp (container-quantity-compare (parse-container-quantity value)
                                                                                      (parse-container-quantity pod-limit))))
                                (invalid-pod "spec.resources.containers[~D][~A].limits: Invalid value: ~S: must be less than or equal to pod limits of ~A"
                                             index name value pod-limit))))
                          (container-resource-map container "limits")))))
    resources))

(defun apply-pod-level-resources (spec requests limits)
  "Replace the aggregate REQUESTS and LIMITS tables with SPEC's pod-level values, as PodRequests does."
  (when (pod-level-resources-set-p spec)
    (loop for (kind table) in (list (list "requests" requests) (list "limits" limits))
          for values = (gethash kind (gethash "resources" spec))
          when values
            do (dolist (name +pod-level-resource-names+)
                 (multiple-value-bind (value present) (gethash name values)
                   (when present (setf (gethash name table) (pod-level-quantity-value value)))))))
  (values requests limits))

(defun pod-level-requirements-qos (resources)
  "Classify pod-level RESOURCES as requirementsQOS does, from CPU and memory alone."
  (let ((classes (loop for name in +pod-level-resource-names+
                       for request = (gethash name (gethash "requests" resources (core-object)))
                       for limit = (gethash name (gethash "limits" resources (core-object)))
                       for request-value = (if request (pod-level-quantity-value request) 0)
                       for limit-value = (if limit (pod-level-quantity-value limit) 0)
                       collect (cond ((/= request-value limit-value) "Burstable")
                                     ((zerop request-value) "BestEffort")
                                     (t "Guaranteed")))))
    (cond ((member "Burstable" classes :test #'equal) "Burstable")
          ((every (lambda (class) (equal class (first classes))) classes) (first classes))
          (t "Burstable"))))

(defun container-with-pod-level-limits (spec container)
  "Return CONTAINER, or a copy whose missing CPU and memory limits are the Pod's own.
The downward API reports these, and a container's cgroup is bounded by them."
  (let ((limits (pod-level-resource-list spec "limits"))
        (own (container-resource-map container "limits")))
    (if (or (null limits)
            (every (lambda (name) (or (not (nth-value 1 (gethash name limits))) (gethash name own)))
                   +pod-level-resource-names+))
        container
        (let* ((copy (copy-core-object container))
               (resources (or (gethash "resources" copy) (setf (gethash "resources" copy) (core-object))))
               (merged (or (gethash "limits" resources) (setf (gethash "limits" resources) (core-object)))))
          (dolist (name +pod-level-resource-names+ copy)
            (multiple-value-bind (value present) (gethash name limits)
              (when (and present (not (gethash name merged)))
                (setf (gethash name merged) value))))))))
