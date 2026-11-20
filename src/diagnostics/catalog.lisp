;;;; SPDX-License-Identifier: MIT
(in-package #:gr8s-diagnose)

;;; Single-resource findings. The checks are in rules/catalog.pl; this file
;;; turns one resource into the observations they are stated in.

(defvar *catalog-entries* nil)

(defun catalog-entries ()
  "Every check as (id kind premises summary step), in the order of the rule file."
  (or *catalog-entries*
      (setf *catalog-entries*
            (known '(check ?id ?kind ?premises ?summary ?step) '(?id ?kind ?premises ?summary ?step)))))

(defvar *advisories* (make-hash-table :test #'equal))

(defun catalog-severity (id)
  (multiple-value-bind (advisory known) (gethash id *advisories*)
    (unless known
      (setf advisory (and (known `(advisory ,id) t) t)
            (gethash id *advisories*) advisory))
    (if advisory "advisory" "warning")))

(defun resource-observations (resource kind)
  "The facts a check may test. Only selected status fields are projected;
messages and Secret values are never asserted."
  (let ((seen (make-hash-table :test #'equal)) (facts (list (list 'kind kind))))
    (labels ((emit (location path value)
               (when value
                 (let ((fact (list 'observed location path (truth value))))
                   (unless (gethash fact seen)
                     (setf (gethash fact seen) t)
                     (push fact facts))))))
      (collect-additional-observations resource kind #'emit)
      (dolist (path '(("status" "phase") ("status" "reason") ("spec" "unschedulable")))
        (emit "object" (format nil "~{~A~^.~}" path) (apply #'field resource path)))
      (loop for condition across (or (field resource "status" "conditions") #())
            for type = (field condition "type")
            when (stringp type)
              do (emit "object" (concatenate 'string "condition." type) (field condition "status"))
                 (emit "object" (concatenate 'string "condition-reason." type) (field condition "reason")))
      (loop for taint across (or (field resource "spec" "taints") #())
            do (emit "object" "taint.key" (field taint "key")))
      (when (equal kind "Event")
        (emit "object" "reason" (field resource "reason"))
        (emit "object" "type" (field resource "type")))
      (when (equal kind "Pod")
        (dolist (section '("containerStatuses" "initContainerStatuses" "ephemeralContainerStatuses"))
          (loop for container across (or (field resource "status" section) #())
                for location = (format nil "~A/~A" section (field container "name"))
                do (dolist (state '("waiting" "terminated"))
                     (emit location (format nil "container.~A.reason" state)
                           (field container "state" state "reason")))
                   (emit location "container.terminated.exitCode"
                         (field container "state" "terminated" "exitCode"))
                   (emit location "container.last-terminated.reason"
                         (field container "lastState" "terminated" "reason"))))))
    (nreverse facts)))

(defun plain-location (kind target location)
  "Name the resource, and the container when LOCATION is SECTION/CONTAINER."
  (let ((slash (position #\/ location)))
    (if slash
        (format nil "~A ~S in ~A ~A"
                (cond ((uiop:string-prefix-p "init" location) "Init container")
                      ((uiop:string-prefix-p "ephemeral" location) "Ephemeral container")
                      (t "Container"))
                (subseq location (1+ slash)) kind target)
        (format nil "~A ~A" kind target))))

(defun condition-since (resource id)
  "When the first condition a check tests last changed, if the API says."
  (loop for premise in (third (assoc id (catalog-entries) :test #'equal))
        for path = (svref premise 1)
        when (uiop:string-prefix-p "condition." path)
          return (field (find (subseq path (length "condition.")) (or (field resource "status" "conditions") #())
                              :test #'equal :key (lambda (c) (field c "type")))
                        "lastTransitionTime")))

(defun catalog-findings (resource kind evidence)
  (let ((target (or (field resource "metadata" "name") "unnamed")))
    (loop for (id location summary step)
            in (prove (resource-observations resource kind)
                      '((finding ?id ?location ?summary ?step)) '(?id ?location ?summary ?step))
          collect (object "code" id "rule" id "severity" (catalog-severity id)
                          "since" (condition-since resource id)
                          "summary" (format nil "~A: ~A" (plain-location kind target location) summary)
                          "nextStep" step "evidence" (vector evidence)))))

(defun namespaced-kind-p (kind)
  (not (member kind '("Node" "Namespace" "PersistentVolume" "CertificateSigningRequest" "StorageClass" "RuntimeClass"
                         "ClusterRole" "ClusterRoleBinding" "MemberView") :test #'equal)))

(defun diagnose-resource (kind name namespace getter)
  (if (equal kind "Pod")
      (diagnose-pod name namespace getter)
      (multiple-value-bind (resource state) (funcall getter kind namespace name)
        (let* ((uid (field resource "metadata" "uid"))
               (version (field resource "metadata" "resourceVersion"))
               (evidence (object "id" "e1" "kind" kind "name" name "namespace" namespace
                                 "uid" uid "resourceVersion" version "observedAt" (timestamp)
                                 "result" (string-downcase (symbol-name state))))
               (findings nil) (complete (eq state :present)))
          (when complete
            (unless (and (equal name (field resource "metadata" "name")) (stringp uid)
                         (or (not (namespaced-kind-p kind))
                             (equal namespace (field resource "metadata" "namespace"))))
              (error "Resource response identity does not match target."))
            (setf findings (catalog-findings resource kind "e1"))
            (multiple-value-bind (after after-state) (funcall getter kind namespace name)
              (unless (and (eq after-state :present)
                           (equal uid (field after "metadata" "uid"))
                           (equal version (field after "metadata" "resourceVersion")))
                (setf complete nil findings nil
                      (gethash "result" evidence) "changed-during-collection"))))
          (object "target" (if (namespaced-kind-p kind)
                             (format nil "~A/~A/~A" kind namespace name)
                             (format nil "~A/~A" kind name))
                  "status" (cond ((not complete) "incomplete") (findings "findings") (t "no-findings"))
                  "scope" "Selected observed conditions and states only; Events are historical. No finding is not a health verdict."
                  "findings" (coerce findings 'vector) "evidence" (vector evidence)
                  "unknownEvidence" (if complete #() #("e1")))))))
